#include <string>
#include <windows.h>
#include <detours.h>
#include <winrt/base.h>

#include "payloadguid.hpp"

std::wstring GetProcessFileName(HANDLE process)
{
	DWORD exeLocation_size = MAX_PATH;

	std::wstring exeLocation;
	exeLocation.resize(exeLocation_size);

	winrt::check_bool(QueryFullProcessImageNameW(process, 0, exeLocation.data(), &exeLocation_size));

	exeLocation.resize(exeLocation_size);
	return exeLocation;
}

template<typename T>
volatile T* InjectPayload(HANDLE hProcess, T payload, REFGUID guid)
{
	auto newPayload = static_cast<volatile T*>(DetourCopyPayloadToProcessEx(hProcess, guid, &payload, sizeof(payload)));
	winrt::check_bool(newPayload);

	return newPayload;
}

int main()
{
	std::wstring target = GetProcessFileName(GetCurrentProcess());
	target.erase(target.rfind(L'\\') + 1);
	target += L"payloadtarget.exe";

	STARTUPINFOW si = { sizeof(si) };
	PROCESS_INFORMATION pi;
	winrt::check_bool(CreateProcessW(target.c_str(), nullptr, nullptr, nullptr, false, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi));
	winrt::handle hProcess(pi.hProcess);
	winrt::handle hThread(pi.hThread);

	// give the child a handle to ourself
	HANDLE targetHandleToParent;
	winrt::check_bool(DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), hProcess.get(), &targetHandleToParent, 0, false, DUPLICATE_SAME_ACCESS));
	InjectPayload(hProcess.get(), targetHandleToParent, PARENT_HANDLE_PAYLOAD);

	// inject a payload in ourself containing zero data
	// the goal is for the child process to find this payload
	// and fill it with random data, to test DetourFindRemotePayload
	auto payloadAddr = InjectPayload<random_payload_t>(GetCurrentProcess(), 0, RANDOM_DATA_PAYLOAD);

	winrt::check_bool(ResumeThread(hThread.get()));
	if (WaitForSingleObject(hProcess.get(), INFINITE) == WAIT_FAILED)
	{
		winrt::throw_last_error();
	}

	DWORD exitCode;
	winrt::check_bool(GetExitCodeProcess(hProcess.get(), &exitCode));

	// the exit code should match the random data the child process gave us
	if (exitCode != *payloadAddr)
	{
		return 1;
	}
}