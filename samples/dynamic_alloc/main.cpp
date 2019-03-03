//////////////////////////////////////////////////////////////////////////////
//
//  Detours Test Program
//
//  Microsoft Research Detours Package
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <functional>
#include <assert.h>
#include <windows.h>
#include <detours.h>

extern "C" {
  void *CodeTemplate();
  void *CodeTemplate_End();
}

void Log(LPCTSTR format, ...) {
  TCHAR linebuf[1024];
  va_list v;
  va_start(v, format);
  wvsprintf(linebuf, format, v);
  va_end(v);
  OutputDebugString(linebuf);
}

void *target_function() {
  std::cout << '+' << __FUNCTION__ << std::endl;
  return nullptr;
}

bool DetourTransaction(std::function<bool()> callback) {
  LONG status = DetourTransactionBegin();
  if (status != NO_ERROR) {
    Log("DetourTransactionBegin failed with %08x\n", status);
    return status;
  }

  if (callback()) {
    status = DetourTransactionCommit();
    if (status != NO_ERROR) {
      Log("DetourTransactionCommit failed with %08x\n", status);
    }
  }
  else {
    status = DetourTransactionAbort();
    if (status == NO_ERROR) {
      Log("Aborted transaction.\n");
    }
    else {
      Log("DetourTransactionAbort failed with %08x\n", status);
    }
  }
  return status == NO_ERROR;
}

class CodeRegionFactory final {
  template <typename T>
  static const T *at(const void *base, uint32_t offset) {
    return
      reinterpret_cast<const T*>(
        reinterpret_cast<const uint8_t*>(base) + offset);
  }

  template <typename T>
  static T *at(void *base, uint32_t offset) {
    return
      reinterpret_cast<T*>(
        reinterpret_cast<uint8_t*>(base) + offset);
  }

  void *region_{};
  uint8_t *current_{},
          *current_end_{};

public:
  CodeRegionFactory(const void *source) {
    DWORD new_region_size{};
    auto new_region_address =
      DetourAllocateRegionWithinJumpBounds(source, &new_region_size);
    if (new_region_address) {
      region_ = current_ = at<uint8_t>(new_region_address, 0);
      current_end_ = current_ + new_region_size;
    }
    else {
      Log("Cannot find a region near %p\n", source);
    }
  }

  ~CodeRegionFactory() {
    if (region_
        && !VirtualFree(region_, 0, MEM_RELEASE)) {
      Log("VirtualFree failed - %08x\n", GetLastError());
    }
  }

  void *PushTemplate(const void *start,
                     const void *end) {
    size_t diff =
      at<uint8_t>(end, 0) - at<uint8_t>(start, 0);
    if (diff < 0 || current_ + diff > current_end_)
      return nullptr;
    auto start_pos = current_;
    memcpy(start_pos, start, diff);
    current_ += diff;
    return start_pos;
  }
};

int main(int, char**) {
  std::cout << "1. target_function() without Detour" << std::endl;
  auto ret = target_function();
  std::cout << ret << std::endl;
  assert(!ret);

  CodeRegionFactory factory(target_function);

  void *detour_destination,
       *detour_target = reinterpret_cast<void*>(target_function);

  // Fill the allocated page with a code template till the end
  // and pick the last instance
  while (auto p = factory.PushTemplate(CodeTemplate,
                                       CodeTemplate_End)) {
    detour_destination = p;
  }

  bool is_detoured = false;
  DetourTransaction([&]() {
    PDETOUR_TRAMPOLINE trampoline{};
    void *target{},
         *detour{};
    auto status = DetourAttachEx(&detour_target,
                                 detour_destination,
                                 &trampoline,
                                 &target,
                                 &detour);
    if (status != NO_ERROR) {
      Log("DetourAttachEx failed - %08x\n", status);
      return false;
    }
    is_detoured = true;
    std::cout
      << "detour: " << target << " --> " << detour
      << " (trampoline: " << trampoline << " )"
      << std::endl;
    return true;
  });

  // Attach failed for some reason.  Bail out.
  if (!is_detoured)
    return 1;

  std::cout << "2. target_function() with Detour" << std::endl;
  ret = target_function();
  std::cout << ret << std::endl;
  assert(ret); // The return value is cracked by the detour function

  DetourTransaction([&]() {
    auto status = DetourDetach(&detour_target, detour_destination);
    if (status != NO_ERROR) {
      Log("DetourDetach failed - %08x\n", status);
      return false;
    }
    return true;
  });

  std::cout << "3. target_function() without Detour" << std::endl;
  ret = target_function();
  std::cout << ret << std::endl;
  assert(!ret);

  return 0;
}