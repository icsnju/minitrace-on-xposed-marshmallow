/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mini_trace.h"


#include <fstream>
#include <sys/uio.h>
#include <grp.h>
#include <unistd.h>
#include <stdlib.h>

#include "base/stl_util.h"
#include "base/unix_file/fd_file.h"
#include "class_linker.h"
#include "common_throws.h"
#include "debugger.h"
#include "dex_file-inl.h"
#include "instrumentation.h"
#include "art_method-inl.h"
#include "mirror/class-inl.h"
#include "mirror/dex_cache.h"
#include "mirror/object_array-inl.h"
#include "mirror/object-inl.h"
#include "os.h"
#include "scoped_thread_state_change.h"
#include "ScopedLocalRef.h"
#include "thread.h"
#include "thread_list.h"
#if !defined(ART_USE_PORTABLE_COMPILER)
#include "entrypoints/quick/quick_entrypoints.h"
#endif

namespace art {

// MiniTrace

enum MiniTraceAction {
    kMiniTraceMethodEnter = 0x00,       // method entry
    kMiniTraceMethodExit = 0x01,        // method exit
    kMiniTraceUnroll = 0x02,            // method exited by exception unrolling
    kMiniTraceFieldRead = 0x03,         // field read
    kMiniTraceFieldWrite = 0x04,        // field write
    kMiniTraceMonitorEnter = 0x05,      // monitor enter
    kMiniTraceMonitorExit = 0x06,       // monitor exit
    kMiniTraceActionMask = 0x07,        // three bits
};

static const int      kMiniTraceRecordSize            = 14;
static const char     kMiniTraceTokenChar             = '*';

static constexpr const char* kMiniTracerInstrumentationKey = "MiniTracer";

MiniTrace* volatile MiniTrace::the_trace_ = NULL;
std::vector<std::string>* volatile MiniTrace::whitelist_ = NULL;

static ArtMethod* DecodeMiniTraceMethodId(uint32_t tmid) {
  return reinterpret_cast<ArtMethod*>(tmid & ~kMiniTraceActionMask);
}

static ArtField* DecodeMiniTraceFieldId(uint32_t tfid) {
  return reinterpret_cast<ArtField*>(tfid & ~kMiniTraceActionMask);
}

static MiniTraceAction DecodeMiniTraceAction(uint32_t tmid) {
  return static_cast<MiniTraceAction>(tmid & kMiniTraceActionMask);
}

static uint32_t EncodeMiniTraceMethodAndAction(ArtMethod* method,
                                           MiniTraceAction action) {
  uint32_t tmid = PointerToLowMemUInt32(method) | action;
  DCHECK_EQ(method, DecodeMiniTraceMethodId(tmid));
  return tmid;
}

static uint32_t EncodeMiniTraceFieldAndAction(ArtField* field,
                                           MiniTraceAction action) {
  uint32_t tfid = PointerToLowMemUInt32(field) | action;
  return tfid;
}

static uint32_t EncodeMiniTraceObjectAndAction(mirror::Object* object,
                                           MiniTraceAction action) {
  uint32_t toid = PointerToLowMemUInt32(object) | action;
  return toid;
}

static uint32_t EncodeMiniTraceObject(mirror::Object* object) {
  return PointerToLowMemUInt32(object);
}

// TODO: put this somewhere with the big-endian equivalent used by JDWP.
static void Append2LE(uint8_t* buf, uint16_t val) {
  *buf++ = static_cast<uint8_t>(val);
  *buf++ = static_cast<uint8_t>(val >> 8);
}

// TODO: put this somewhere with the big-endian equivalent used by JDWP.
static void Append4LE(uint8_t* buf, uint32_t val) {
  *buf++ = static_cast<uint8_t>(val);
  *buf++ = static_cast<uint8_t>(val >> 8);
  *buf++ = static_cast<uint8_t>(val >> 16);
  *buf++ = static_cast<uint8_t>(val >> 24);
}

static void Append8LE(uint8_t* buf, uint64_t val) {
  *buf++ = static_cast<uint8_t>(val);
  *buf++ = static_cast<uint8_t>(val >> 8);
  *buf++ = static_cast<uint8_t>(val >> 16);
  *buf++ = static_cast<uint8_t>(val >> 24);
  *buf++ = static_cast<uint8_t>(val >> 32);
  *buf++ = static_cast<uint8_t>(val >> 40);
  *buf++ = static_cast<uint8_t>(val >> 48);
  *buf++ = static_cast<uint8_t>(val >> 56);
}

static bool PostClassPrepareClassVisitor(mirror::Class* klass, void * data)
        SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) {
  UNUSED(data);
  MiniTrace::PostClassPrepare(klass);
  return true;
}

static bool DumpCoverageDataClassVisitor(mirror::Class* klass, void * data)
        SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) {
  if (!klass->IsMiniTraceable()) {
    return true;
  }
  std::ostream* os = (std::ostream*)data;
  ClassLinker* cl = Runtime::Current()->GetClassLinker();
  size_t pointer_size = cl->GetImagePointerSize();

  for (size_t i = 0, e = klass->NumDirectMethods(); i < e; i++) {
    ArtMethod* method = klass->GetDirectMethod(i, pointer_size);
    MiniTrace::DumpCoverageData(*os, method);
  }

  for (size_t i = 0, e = klass->NumVirtualMethods(); i < e; i++) {
    ArtMethod* method = klass->GetVirtualMethod(i, pointer_size);
    MiniTrace::DumpCoverageData(*os, method);
  }

  return true;
}

void MiniTrace::DumpCoverageData(std::ostream& os, ArtMethod* method) {
  const DexFile::CodeItem* code_item = method->GetCodeItem();
  if (code_item == nullptr) {
    return;
  }
  uint16_t insns_size = code_item->insns_size_in_code_units_;

  os << StringPrintf("%p\t%s\t%s\t%s\t%s\t%d\t", method,
      PrettyDescriptor(method->GetDeclaringClassDescriptor()).c_str(), method->GetName(),
      method->GetSignature().ToString().c_str(), method->GetDeclaringClassSourceFile(), insns_size);

  const uint8_t* data = method->GetCoverageData();
  if (data == nullptr) {
    return;
  }
  for (int i = 0; i < insns_size; i++) {
    if (data[i] > 0) {
      os << 1;
    } else {
      os << 0;
    }
  }
  os << '\n';
}

void MiniTrace::DumpCoverageData() {
  std::string coverage_data_filename(StringPrintf("/data/mini_trace_%d_coverage.dat",
                                         getuid()));
  std::unique_ptr<File> file(OS::CreateEmptyFile(coverage_data_filename.c_str()));

  if (file.get() == nullptr) {
    LOG(INFO) << "Failed to open coverage data file " << coverage_data_filename;
    return;
  }

  LOG(INFO) << "MiniTrace: Try to dump coverage data";
  std::ostringstream os;

  Runtime* runtime = Runtime::Current();
  runtime->GetThreadList()->SuspendAll(__FUNCTION__);
  runtime->GetClassLinker()->VisitClasses(DumpCoverageDataClassVisitor, &os);
  runtime->GetThreadList()->ResumeAll();

  std::string data(os.str());
  if (!file->WriteFully(data.c_str(), data.length())) {
    LOG(INFO) << "Failed to write coverage data file " << coverage_data_filename;
    file->Erase();
    return;
  }
  if (file->FlushCloseOrErase() != 0) {
    LOG(INFO) << "Failed to flush coverage data file " << coverage_data_filename;
    return;
  }
}

void MiniTrace::DumpCoverageData(std::ostream& os) {
  UNUSED(os);
}

void MiniTrace::Start() {
  LOG(INFO) << "MiniTrace: Try to start";
  Thread* self = Thread::Current();
  {
    MutexLock mu(self, *Locks::trace_lock_);
    if (the_trace_ != NULL) {
      LOG(ERROR) << "Trace already in progress, ignoring this request";
      return;
    }
  }

  const char* trace_base_filename = "/data/mini_trace_";

  uint32_t events = 0;
  int buffer_size = 1024;
  std::vector<std::string>* whitelist = new std::vector<std::string>();
  {
    std::ostringstream os;
    os << trace_base_filename << getuid()  << "_config.in";
    std::string trace_config_filename(os.str());

    if (OS::FileExists(trace_config_filename.c_str())) {
      std::ifstream in(trace_config_filename.c_str());
      if (!in) {
        LOG(INFO) << "MiniTrace: config file " << trace_config_filename << " exists but can't be opened";
        return;
      }
      std::string line;

      while (!in.eof()) {
        std::getline(in, line);
        if (in.eof()) {
          break;
        }
        if (line.compare("off") == 0) {
          LOG(INFO) << "MiniTrace has been turned off in the config file " << trace_config_filename;
          return;
        } else if (line.compare("DoCoverage") == 0) {
          LOG(INFO) << "MiniTrace: enable DoCoverage in file " << trace_config_filename;
          events |= kDoCoverage;
        } else if (line.compare("DoFilter") == 0) {
          LOG(INFO) << "MiniTrace: enable DoFilter in file " << trace_config_filename;
          events |= kDoFilter;
        } else if (line.compare("MethodEvent") == 0) {
          LOG(INFO) << "MiniTrace: enable MethodEvent in file " << trace_config_filename;
          events |= kDoMethodEntered | kDoMethodExited | kDoMethodUnwind;
        } else if (line.compare("FieldEvent") == 0) {
          LOG(INFO) << "MiniTrace: enable FieldEvent in file " << trace_config_filename;
          events |= kDoFieldRead | kDoFieldWritten;
        } else if (line.compare("MonitorEvent") == 0) {
          LOG(INFO) << "MiniTrace: enable MonitorEvent in file " << trace_config_filename;
          events |= kDoMonitorEntered | kDoMonitorExited;
        } else if (line.compare(0, 6, "Buffer") == 0) {
          std::string buffer_str = line.substr(6);
          LOG(INFO) << "MiniTrace: buffer (KB): " << buffer_str;
          int factor = atoi(buffer_str.c_str());
          if (factor > 0) {
            buffer_size = buffer_size * factor;
          }
        } else if (line.compare(0, 7, "Include") == 0) {
          std::string class_name_prefix = line.substr(8);
          LOG(INFO) << "MiniTrace: Include class " << class_name_prefix;
          whitelist->push_back(class_name_prefix);
        } else {
          LOG(INFO) << "MiniTrace: ignore unknown option " << line << " in file " << trace_config_filename;
        }
      }
      LOG(INFO) << StringPrintf("MiniTrace: final events: 0x%08x", events);
    } else {
      LOG(INFO) << "MiniTrace: config file " << trace_config_filename << " does not exist";
      return;
    }
  }

  // Method mapping
  std::unique_ptr<File> trace_info_file;
  {
    std::ostringstream os;
    os << trace_base_filename << getuid()  << "_info.log";
    std::string trace_info_filename(os.str());
    trace_info_file.reset(OS::CreateEmptyFile(trace_info_filename.c_str()));
    if (trace_info_file.get() == NULL) {
      LOG(INFO) << "MiniTrace: Unable to open trace info file '" << trace_info_filename << "'";
      return;
    }
  }

  // Trace data
  std::unique_ptr<File> trace_data_file;
  {
    std::ostringstream os;
    os << trace_base_filename << getuid()  << "_data.bin";
    std::string trace_data_filename(os.str());
    trace_data_file.reset(OS::CreateEmptyFile(trace_data_filename.c_str()));
    if (trace_data_file.get() == NULL) {
      LOG(INFO) << "MiniTrace: Unable to open trace data file '" << trace_data_filename << "'";
      return;
    }
  }

  Runtime* runtime = Runtime::Current();

  runtime->GetThreadList()->SuspendAll(__FUNCTION__);

  // Create Trace object.
  {
    MutexLock mu(self, *Locks::trace_lock_);
    if (the_trace_ != NULL) {
      LOG(ERROR) << "Trace already in progress, ignoring this request";
    } else {

      // if (events == 0) {  // Do everything we can if there is no events
      //   events = instrumentation::Instrumentation::kMethodEntered |
      //            instrumentation::Instrumentation::kMethodExited |
      //            instrumentation::Instrumentation::kMethodUnwind;
      // }

      // a shared white list
      whitelist_ = whitelist;

      the_trace_ = new MiniTrace(trace_info_file.release(),
                                 trace_data_file.release(),
                                 events,
                                 buffer_size);

      runtime->GetInstrumentation()->AddListener(the_trace_, events);
      runtime->GetInstrumentation()->EnableMethodTracing(kMiniTracerInstrumentationKey);

      runtime->GetClassLinker()->VisitClasses(PostClassPrepareClassVisitor, NULL);

    }
  }

  runtime->GetThreadList()->ResumeAll();
}

void MiniTrace::Stop() {
  Runtime* runtime = Runtime::Current();
  runtime->GetThreadList()->SuspendAll(__FUNCTION__);
  MiniTrace* the_trace = NULL;
  std::vector<std::string>* whitelist = NULL;
  {
    MutexLock mu(Thread::Current(), *Locks::trace_lock_);
    if (the_trace_ == NULL) {
      LOG(ERROR) << "Trace stop requested, but no trace currently running";
    } else {
      the_trace = the_trace_;
      the_trace_ = NULL;
      whitelist = whitelist_;
      whitelist_ = NULL;
      if (whitelist != NULL) {
        delete whitelist;
      }
    }
  }
  if (the_trace != NULL) {
    the_trace->FinishTracing();

    runtime->GetInstrumentation()->DisableMethodTracing(kMiniTracerInstrumentationKey);
    runtime->GetInstrumentation()->RemoveListener(the_trace, the_trace->events_);

    if (the_trace->trace_info_file_.get() != nullptr) {
      // Do not try to erase, so flush and close explicitly.
      if (the_trace->trace_info_file_->Flush() != 0) {
        PLOG(ERROR) << "Could not flush trace info file.";
      }
      if (the_trace->trace_info_file_->Close() != 0) {
        PLOG(ERROR) << "Could not close trace info file.";
      }
    }
    if (the_trace->trace_data_file_.get() != nullptr) {
      // Do not try to erase, so flush and close explicitly.
      if (the_trace->trace_data_file_->Flush() != 0) {
        PLOG(ERROR) << "Could not flush trace data file.";
      }
      if (the_trace->trace_data_file_->Close() != 0) {
        PLOG(ERROR) << "Could not close trace data file.";
      }
    }
    delete the_trace;
  }
  runtime->GetThreadList()->ResumeAll();
}

void MiniTrace::Shutdown() {
  if (GetMethodTracingMode() != kTracingInactive) {
    Stop();
  }
}

TracingMode MiniTrace::GetMethodTracingMode() {
  MutexLock mu(Thread::Current(), *Locks::trace_lock_);
  if (the_trace_ == NULL) {
    return kTracingInactive;
  } else {
    return kMethodTracingActive;
  }
}

MiniTrace::MiniTrace(File* trace_info_file, File* trace_data_file,
      uint32_t events, int buffer_size)
    : trace_info_file_(trace_info_file), trace_data_file_(trace_data_file),
      buf_(new uint8_t[buffer_size]()), events_(events), do_coverage_((events & kDoCoverage) != 0),
      do_filter_((events & kDoFilter) != 0), buffer_size_(buffer_size), start_time_(MicroTime()),
      cur_offset_(0), buffer_overflow_count_(0) {
}


void MiniTrace::DumpList() {
  Thread* self = Thread::Current();
  MiniTrace* trace = NULL;
  {
    MutexLock mu(self, *Locks::trace_lock_);
    if (the_trace_ == NULL) {
      LOG(ERROR) << "MiniTrace is not in progress, ignoring this request";
      return;
    }
    trace = the_trace_;
  }

  {
    ScopedObjectAccess soa(self);   // Acquire the mutator lock.
    trace->DumpList(LOG(INFO));
  }
}

void MiniTrace::DumpList(std::ostream& os) {
  os << StringPrintf("%cthreads\n", kMiniTraceTokenChar);
  DumpThreadList(os);
  os << StringPrintf("%cmethods\n", kMiniTraceTokenChar);
  DumpMethodList(os);
  os << StringPrintf("%cfields\n", kMiniTraceTokenChar);
  DumpFieldList(os);
  os << StringPrintf("%cend\n", kMiniTraceTokenChar);
}

void MiniTrace::FinishTracing() {
  FlushBuffer();

  std::ostringstream os;
  DumpList(os);

  std::string header(os.str());
  if (!trace_info_file_->WriteFully(header.c_str(), header.length())) {
    std::string detail(StringPrintf("Trace info write failed: %s", strerror(errno)));
    PLOG(ERROR) << detail;
    ThrowRuntimeException("%s", detail.c_str());
  }
}

void MiniTrace::DexPcMoved(Thread* thread, mirror::Object* this_object,
                       ArtMethod* method, uint32_t new_dex_pc) {
  UNUSED(thread, this_object, method, new_dex_pc);
}

void MiniTrace::FieldRead(Thread* thread, mirror::Object* this_object,
                       ArtMethod* method, uint32_t dex_pc, ArtField* field) {
  UNUSED(method);
  LogFieldTraceEvent(thread, this_object, field, dex_pc, true);
}

void MiniTrace::FieldWritten(Thread* thread, mirror::Object* this_object,
                          ArtMethod* method, uint32_t dex_pc, ArtField* field,
                          const JValue& field_value) {
  UNUSED(method, field_value);
  LogFieldTraceEvent(thread, this_object, field, dex_pc, false);
}

void MiniTrace::MethodEntered(Thread* thread, mirror::Object* this_object,
                          ArtMethod* method, uint32_t dex_pc) {
  UNUSED(this_object);
  LogMethodTraceEvent(thread, method, dex_pc, instrumentation::Instrumentation::kMethodEntered, 0);
}

void MiniTrace::MethodExited(Thread* thread, mirror::Object* this_object,
                         ArtMethod* method, uint32_t dex_pc,
                         const JValue& return_value) {
  UNUSED(this_object);
  LogMethodTraceEvent(thread, method, dex_pc, instrumentation::Instrumentation::kMethodExited, return_value.GetJ());
}

void MiniTrace::MethodUnwind(Thread* thread, mirror::Object* this_object,
                         ArtMethod* method, uint32_t dex_pc) {
  UNUSED(this_object);
  LogMethodTraceEvent(thread, method, dex_pc, instrumentation::Instrumentation::kMethodUnwind, 0);
}

void MiniTrace::ExceptionCaught(Thread* thread, mirror::Throwable* exception_object) {
  UNUSED(thread, exception_object);
  LOG(ERROR) << "Unexpected exception caught event in tracing";
}

void MiniTrace::BackwardBranch(Thread* thread, ArtMethod* method, int32_t dex_pc_offset) {
  UNUSED(thread, method, dex_pc_offset);
}

bool MiniTrace::HandleOverflow() {
  Thread* self = Thread::Current();

  int local_count = buffer_overflow_count_;

  if (local_count > 1024) {  // 1024 * 1 MB = 1 GB
    return false;
  }

  {
    MutexLock mu(self, *Locks::trace_lock_);

    if (local_count != buffer_overflow_count_) {
      return true; // already handled by somebody
    }

    buffer_overflow_count_ ++;
    return FlushBuffer();
  }
}

bool MiniTrace::FlushBuffer() {

  int32_t cur_offset = cur_offset_.LoadRelaxed();

  if (cur_offset == 0) {
    return true;
  }

  if (!trace_data_file_->WriteFully(buf_.get(), cur_offset)) {
    std::string detail(StringPrintf("Trace data write failed: %s", strerror(errno)));
    PLOG(ERROR) << detail;
    return false;
  }


  uint8_t* ptr = buf_.get();
  uint8_t* end = buf_.get() + cur_offset;

  while (ptr < end) {
    uint32_t aid = ptr[2] | (ptr[3] << 8) | (ptr[4] << 16) | (ptr[5] << 24);
    MiniTraceAction action = DecodeMiniTraceAction(aid);
    switch (action) {
      case kMiniTraceMethodEnter:
      case kMiniTraceMethodExit:
      case kMiniTraceUnroll:
        visited_methods_.insert(DecodeMiniTraceMethodId(aid));
        break;
      case kMiniTraceFieldRead:
      case kMiniTraceFieldWrite:
        visited_fields_.insert(DecodeMiniTraceFieldId(aid));
        break;
      case kMiniTraceMonitorEnter:
      case kMiniTraceMonitorExit:
        break;
      default:
        UNIMPLEMENTED(FATAL) << "Unexpected action";
    }
    ptr += kMiniTraceRecordSize;
  }

  cur_offset_.StoreRelease(0);
  return true;
}


void MiniTrace::LogMethodTraceEvent(Thread* thread, ArtMethod* method, uint32_t dex_pc,
                                instrumentation::Instrumentation::InstrumentationEvent event,
                                int64_t return_value) {
  UNUSED(dex_pc);
  if (!method->IsMiniTraceable()) {
    return;
  }
  MiniTraceAction action = kMiniTraceMethodEnter;
  switch (event) {
    case instrumentation::Instrumentation::kMethodEntered:
      action = kMiniTraceMethodEnter;
      break;
    case instrumentation::Instrumentation::kMethodExited:
      action = kMiniTraceMethodExit;
      break;
    case instrumentation::Instrumentation::kMethodUnwind:
      action = kMiniTraceUnroll;
      break;
    default:
      UNIMPLEMENTED(FATAL) << "Unexpected event: " << event;
  }

  // Advance cur_offset_ atomically.
  int32_t new_offset;
  int32_t old_offset;
  do {
    old_offset = cur_offset_.LoadRelaxed();
    new_offset = old_offset + kMiniTraceRecordSize;
    if (new_offset > buffer_size_) {
      if (HandleOverflow()) {
        continue;
      }
      return;
    }
  } while (!cur_offset_.CompareExchangeWeakSequentiallyConsistent(old_offset, new_offset));


  uint32_t method_value = EncodeMiniTraceMethodAndAction(method, action);

  // Write data
  uint8_t* ptr = buf_.get() + old_offset;
  Append2LE(ptr, thread->GetTid());
  Append4LE(ptr + 2, method_value);
  Append8LE(ptr + 4, static_cast<uint64_t>(return_value));
}

void MiniTrace::LogFieldTraceEvent(Thread* thread, mirror::Object *this_object, ArtField* field,
                                uint32_t dex_pc, bool read_event) {

  if (!field->IsMiniTraceable()) {
    return;
  }

  MiniTraceAction action;
  if (read_event) {
    action = kMiniTraceFieldRead;
  } else {
    action = kMiniTraceFieldWrite;
  }

  // Advance cur_offset_ atomically.
  int32_t new_offset;
  int32_t old_offset;
  do {
    old_offset = cur_offset_.LoadRelaxed();
    new_offset = old_offset + kMiniTraceRecordSize;
    if (new_offset > buffer_size_) {
      if (HandleOverflow()) {
        continue;
      }
      return;
    }
  } while (!cur_offset_.CompareExchangeWeakSequentiallyConsistent(old_offset, new_offset));

  uint32_t field_value = EncodeMiniTraceFieldAndAction(field, action);

  // Write data
  uint8_t* ptr = buf_.get() + old_offset;
  Append2LE(ptr, thread->GetTid());
  Append4LE(ptr + 2, field_value);
  ptr += 6;

  uint32_t object_value = EncodeMiniTraceObject(this_object);
  Append4LE(ptr, object_value);
  Append4LE(ptr + 4, dex_pc);
}

void MiniTrace::LogMonitorTraceEvent(Thread* thread, mirror::Object* lock_object,
    uint32_t dex_pc, bool enter_event) {
  MiniTraceAction action;
  if (enter_event) {
    action = kMiniTraceMonitorEnter;
  } else {
    action = kMiniTraceMonitorExit;
  }

  // Advance cur_offset_ atomically.
  int32_t new_offset;
  int32_t old_offset;
  do {
    old_offset = cur_offset_.LoadRelaxed();
    new_offset = old_offset + kMiniTraceRecordSize;
    if (new_offset > buffer_size_) {
      if (HandleOverflow()) {
        continue;
      }
      return;
    }
  } while (!cur_offset_.CompareExchangeWeakSequentiallyConsistent(old_offset, new_offset));

  uint32_t object_value = EncodeMiniTraceObjectAndAction(lock_object, action);

  // Write data
  uint8_t* ptr = buf_.get() + old_offset;
  Append2LE(ptr, thread->GetTid());
  Append4LE(ptr + 2, object_value);
  ptr += 6;

  Append4LE(ptr, dex_pc);
}

void MiniTrace::DumpMethodList(std::ostream& os) {
  for (const auto& method : visited_methods_) {
    os << StringPrintf("%p\t%s\t%s\t%s\t%s\n", method,
        PrettyDescriptor(method->GetDeclaringClassDescriptor()).c_str(), method->GetName(),
        method->GetSignature().ToString().c_str(), method->GetDeclaringClassSourceFile());
  }
}

void MiniTrace::DumpFieldList(std::ostream& os) {
  for (const auto& field : visited_fields_) {
    // TODO we may use FieldHelper to help print a field.
    const DexFile* dex_file = field->GetDexFile();
    const DexFile::FieldId& field_id = dex_file->GetFieldId(field->GetDexFieldIndex());
    os << StringPrintf("%p\t%s\t%s\t%s\n", field,
        PrettyDescriptor(dex_file->GetFieldDeclaringClassDescriptor(field_id)).c_str(), field->GetName(),
        field->GetTypeDescriptor());
  }
}

static void DumpThread(Thread* t, void* arg) {
  std::ostream& os = *reinterpret_cast<std::ostream*>(arg);
  std::string name;
  t->GetThreadName(name);
  os << t->GetTid() << "\t" << name << "\n";
}

void MiniTrace::DumpThreadList(std::ostream& os) {
  Thread* self = Thread::Current();
  for (auto it : exited_threads_) {
    os << it.first << "\t" << it.second << "\n";
  }
  Locks::thread_list_lock_->AssertNotHeld(self);
  MutexLock mu(self, *Locks::thread_list_lock_);
  Runtime::Current()->GetThreadList()->ForEach(DumpThread, &os);
}

void MiniTrace::StoreExitingThreadInfo(Thread* thread) {
  MutexLock mu(thread, *Locks::trace_lock_);
  if (the_trace_ != nullptr) {
    std::string name;
    thread->GetThreadName(name);
    the_trace_->exited_threads_.Put(thread->GetTid(), name);
  }
}

void MiniTrace::AllocateCoverageData(ArtMethod* method) {
  const DexFile::CodeItem* code_item = method->GetCodeItem();
  uint16_t insns_size = code_item->insns_size_in_code_units_;
  if (insns_size == 0) {
    return;
  }

  // uint8_t* execution_data = new uint8_t[insns_size];
  // memset(execution_data, 0, insns_size * sizeof(uint8_t));
  // // method->SetMiniTraceCoverageData(execution_data);
}

void MiniTrace::PostClassPrepare(mirror::Class* klass) {
  if (klass->IsArrayClass() || klass->IsInterface() || klass->IsPrimitive() || klass->IsProxyClass()) {
    return;
  }

  std::string temp;
  const char* descriptor = klass->GetDescriptor(&temp);

  // Default, no trace
  bool do_trace = false;

  std::vector<std::string>* whitelist = whitelist_;
  if (whitelist != NULL) {
    if (whitelist->size() == 0) {
      const char* prefix = "/system/framework/";
      const char* location = klass->GetDexFile().GetLocation().c_str();
      if (strncmp(location, prefix, strlen(prefix)) != 0) {
        do_trace = true;
      }
    } else {
      for (const auto& prefix : *whitelist) {
        const char* str = prefix.c_str();
        int length = strlen(str);
        if (strncmp(descriptor, str, length) == 0) {
          do_trace = true;
          break;
        }
      }
    }
  }

  if (do_trace == false) {
    return;
  }

  LOG(INFO) << "MiniTrace: Trace class " << descriptor;

  ClassLinker* cl = Runtime::Current()->GetClassLinker();
  size_t pointer_size = cl->GetImagePointerSize();

  klass->SetIsMiniTraceable();

  for (size_t i = 0, e = klass->NumDirectMethods(); i < e; i++) {
    ArtMethod* method = klass->GetDirectMethod(i, pointer_size);
    method->SetIsMiniTraceable();
    LOG(INFO) << StringPrintf("%p\t%s\t%s\t%s\t%s\n", method,
        PrettyDescriptor(method->GetDeclaringClassDescriptor()).c_str(), method->GetName(),
        method->GetSignature().ToString().c_str(), method->GetDeclaringClassSourceFile());
    AllocateCoverageData(method);
  }

  for (size_t i = 0, e = klass->NumVirtualMethods(); i < e; i++) {
    ArtMethod* method = klass->GetVirtualMethod(i, pointer_size);
    method->SetIsMiniTraceable();
    LOG(INFO) << StringPrintf("%p\t%s\t%s\t%s\t%s\n", method,
        PrettyDescriptor(method->GetDeclaringClassDescriptor()).c_str(), method->GetName(),
        method->GetSignature().ToString().c_str(), method->GetDeclaringClassSourceFile());
    AllocateCoverageData(method);
  }

  {
    size_t num_fields = klass->NumInstanceFields();
    ArtField* fields = klass->GetIFields();

    for (size_t i = 0; i < num_fields; i++) {
      ArtField* f = &fields[i];
      f->SetIsMiniTraceable();
    }
  }

  {
    size_t num_fields = klass->NumStaticFields();
    ArtField* fields = klass->GetSFields();

    for (size_t i = 0; i < num_fields; i++) {
      ArtField* f = &fields[i];
      f->SetIsMiniTraceable();
    }
  }
}


}  // namespace art
