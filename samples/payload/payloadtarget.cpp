#define _CRT_RAND_S
#include <stdlib.h>

#include <windows.h>
#include <detours.h>

#include "payloadguid.hpp"

int main()
{
	DWORD payloadSize;
	void* payloadAddr = DetourFindPayloadEx(PARENT_HANDLE_PAYLOAD, &payloadSize);

	if (payloadAddr && payloadSize == sizeof(HANDLE))
	{
		HANDLE parent = *static_cast<HANDLE*>(payloadAddr);

		DWORD randomPayloadSize;
		void* randomPayload = DetourFindRemotePayload(parent, RANDOM_DATA_PAYLOAD, &randomPayloadSize);
		if (randomPayload && randomPayloadSize == sizeof(random_payload_t))
		{
			random_payload_t randomData;
			if (rand_s(&randomData) == 0)
			{
				if (WriteProcessMemory(parent, randomPayload, &randomData, sizeof(randomData), nullptr))
				{
					CloseHandle(parent);

					// conversion to int return type is potentially undefined
					ExitProcess(randomData);
				}
			}
		}

		CloseHandle(parent);
	}

	return 1;
}