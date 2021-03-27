#include <fltKernel.h>

#define min(a,b) (((a) < (b)) ? (a) : (b))
#define NTWVM_DATA_COPY_SIZE    300

NTSTATUS ReadWVMData(PVOID localBuffer, ULONG bufferSize, PCHAR targetBuffer)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    if (NULL != localBuffer && bufferSize != 0) {
        ULONG readLen = min(bufferSize, NTWVM_DATA_COPY_SIZE);
        try {
            ProbeForRead(localBuffer, readLen, sizeof(ULONG));
            RtlCopyMemory(targetBuffer, localBuffer, readLen);
        } except(EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
            return status;
        }
    }
    return status;
}