#define _CRT_RAND_S
#include <stdlib.h>

#include <windows.h>
#include <detours.h>
#include <winrt/base.h>

#include "payloadguid.hpp"

int main()
{
	DWORD payloadSize;
	void* payloadAddr = DetourFindPayloadEx(PARENT_HANDLE_PAYLOAD, &payloadSize);

	if (payloadAddr && payloadSize == sizeof(HANDLE))
	{
		winrt::handle parent(*static_cast<HANDLE*>(payloadAddr));

		DWORD randomPayloadSize;
		void* randomPayload = DetourFindRemotePayload(parent.get(), RANDOM_DATA_PAYLOAD, &randomPayloadSize);
		if (randomPayload && randomPayloadSize == sizeof(random_payload_t))
		{
			random_payload_t randomData;
			if (!rand_s(&randomData))
			{
				winrt::check_bool(WriteProcessMemory(parent.get(), randomPayload, &randomData, sizeof(randomData), nullptr));

				parent.close();
				// conversion to int return type is potentially undefined
				ExitProcess(randomData);
			}
		}
	}
}