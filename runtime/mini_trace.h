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

#ifndef ART_RUNTIME_MINI_TRACE_H_
#define ART_RUNTIME_MINI_TRACE_H_

#include <memory>
#include <ostream>
#include <set>
#include <string>
#include <vector>
#include <queue>
#include <unordered_map>

#include "atomic.h"
#include "base/macros.h"
#include "base/stringpiece.h"
#include "dex_instruction.h"
#include "globals.h"
#include "instrumentation.h"
#include "trace.h"
#include "os.h"
#include "safe_map.h"

namespace art {

namespace mirror {
  class Class;
}  // namespace mirror

class Thread;
class ArtField;
class ArtMethod;

class MiniTrace : public instrumentation::InstrumentationListener {

  enum MiniTraceFlag {
    kDoMethodEntered =    1 << 0,
    kDoMethodExited =     1 << 1,
    kDoMethodUnwind =     1 << 2,
    kDoDexPcMoved =       1 << 3,
    kDoFieldRead =        1 << 4,
    kDoFieldWritten =     1 << 5,
    kDoExceptionCaught =  1 << 6,
    kDoMonitorEntered =   1 << 7,
    kDoMonitorExited =    1 << 8,
    kDoCoverage =         1 << 9,
    kDoFilter =           1 << 10,
  };

 public:
  static void Start()
      LOCKS_EXCLUDED(Locks::mutator_lock_,
                     Locks::thread_list_lock_,
                     Locks::thread_suspend_count_lock_,
                     Locks::trace_lock_);
  static void Stop()
      LOCKS_EXCLUDED(Locks::mutator_lock_,
                     Locks::thread_list_lock_,
                     Locks::trace_lock_);
  static void Shutdown() LOCKS_EXCLUDED(Locks::trace_lock_);
  static void DumpList()
      LOCKS_EXCLUDED(Locks::mutator_lock_,
                     Locks::thread_list_lock_,
                     Locks::trace_lock_);

  static TracingMode GetMethodTracingMode() LOCKS_EXCLUDED(Locks::trace_lock_);

  static void PostClassPrepare(mirror::Class* klass)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  // InstrumentationListener implementation.
  void MethodEntered(Thread* thread, mirror::Object* this_object,
                     ArtMethod* method, uint32_t dex_pc)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) OVERRIDE;
  void MethodExited(Thread* thread, mirror::Object* this_object,
                    ArtMethod* method, uint32_t dex_pc,
                    const JValue& return_value)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) OVERRIDE;
  void MethodUnwind(Thread* thread, mirror::Object* this_object,
                    ArtMethod* method, uint32_t dex_pc)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) OVERRIDE;
  void DexPcMoved(Thread* thread, mirror::Object* this_object,
                  ArtMethod* method, uint32_t new_dex_pc)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) OVERRIDE;
  void FieldRead(Thread* thread, mirror::Object* this_object,
                 ArtMethod* method, uint32_t dex_pc, ArtField* field)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) OVERRIDE;
  void FieldWritten(Thread* thread, mirror::Object* this_object,
                    ArtMethod* method, uint32_t dex_pc, ArtField* field,
                    const JValue& field_value)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) OVERRIDE;
  void ExceptionCaught(Thread* thread, mirror::Throwable* exception_object)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) OVERRIDE;
  void BackwardBranch(Thread* thread, ArtMethod* method, int32_t dex_pc_offset)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) OVERRIDE;

  // ExtInstrumentationListener implementation.
  void MonitorEntered(Thread* thread, mirror::Object* lock_object,
                     uint32_t dex_pc)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);
  void MonitorExited(Thread* thread, mirror::Object* lock_object,
                    uint32_t dex_pc)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  static void StoreExitingThreadInfo(Thread* thread);

  static void DumpCoverageData(std::ostream& os, ArtMethod* method) SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);
  static void DumpCoverageData() LOCKS_EXCLUDED(Locks::mutator_lock_,
                     Locks::thread_list_lock_,
                     Locks::thread_suspend_count_lock_);

 private:
  explicit MiniTrace(File* trace_info_file, File* trace_data_file, uint32_t events, int buffer_size);

  static void AllocateCoverageData(ArtMethod* method) SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  void FinishTracing() SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  void LogMethodTraceEvent(Thread* thread, ArtMethod* method, uint32_t dex_pc,
                           instrumentation::Instrumentation::InstrumentationEvent event,
                           int64_t return_value)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  void LogFieldTraceEvent(Thread* thread, mirror::Object* this_object, ArtField* field,
                           uint32_t dex_pc, bool read_event)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  void LogMonitorTraceEvent(Thread* thread, mirror::Object* lock_object, uint32_t dex_pc,
                           bool enter_event)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  bool HandleOverflow() LOCKS_EXCLUDED(Locks::trace_lock_);

  bool FlushBuffer();

  void DumpList(std::ostream& os)  SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);
  void DumpMethodList(std::ostream& os) SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);
  void DumpFieldList(std::ostream& os) SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);
  static void DumpCoverageData(std::ostream& os) SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);
  void DumpThreadList(std::ostream& os) LOCKS_EXCLUDED(Locks::thread_list_lock_);

  // Singleton instance of the Trace or NULL when no method tracing is active.
  static MiniTrace* volatile the_trace_;

  static std::vector<std::string>* volatile whitelist_;

  // File to write method info and field info out to.
  std::unique_ptr<File> trace_info_file_;

  // File to write trace data out to.
  std::unique_ptr<File> trace_data_file_;

  // Buffer to store trace data.
  std::unique_ptr<uint8_t> buf_;

  // Events, default open every available events.
  uint32_t events_;

  // Log execution data
  bool do_coverage_;

  // Filter library code
  bool do_filter_;

  // Size of buf_.
  const int buffer_size_;

  // Time trace was created.
  const uint64_t start_time_;

  // Offset into buf_.
  AtomicInteger cur_offset_;

  // Overflow counter
  int buffer_overflow_count_;

  // Visited methods
  std::set<ArtMethod*> visited_methods_;

  // Visited fields
  std::set<ArtField*> visited_fields_;

  // Map of thread ids and names that have already exited.
  SafeMap<pid_t, std::string> exited_threads_;

  DISALLOW_COPY_AND_ASSIGN(MiniTrace);
};


}  // namespace art

#endif  // ART_RUNTIME_MINI_TRACE_H_
