
#include <ntddk.h>
#include <wdm.h>

#define IOCTL_ALLOC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TOUGHER_ALLOC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH IrpNotImplementedHandler;
NTSTATUS IrpCreateCloseHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
NTSTATUS IrpDeviceIoCtlHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);

extern "C"
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	PDEVICE_OBJECT DeviceObject = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	UINT32 i = 0;
	UNICODE_STRING DeviceName, DosDeviceName = { 0 };

	UNREFERENCED_PARAMETER(RegistryPath);

	RtlInitUnicodeString(&DeviceName, L"\\Device\\Overfl0w");
	RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\Overfl0w");

	// Create the device
	Status = IoCreateDevice(DriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DeviceObject);

	if (!NT_SUCCESS(Status)) {
		if (DeviceObject) {
			// Delete the device
			IoDeleteDevice(DeviceObject);
		}
		return Status;
	}

	// Assign the IRP handlers
	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
		DriverObject->MajorFunction[i] = IrpNotImplementedHandler;
	}

	// Assign the IRP handlers for Create, Close and Device Control
	DriverObject->MajorFunction[IRP_MJ_CREATE] = IrpCreateCloseHandler;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = IrpCreateCloseHandler;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceIoCtlHandler;

	// Assign the driver Unload routine
	DriverObject->DriverUnload = DriverUnload;


	// Set the flags
	DeviceObject->Flags |= DO_DIRECT_IO;
	DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	// Create the symbolic link
	Status = IoCreateSymbolicLink(&DosDeviceName, &DeviceName);

	DbgPrint("[+] Vulnerable Driver Loaded\n");

	return Status;
}

NTSTATUS Alloc(size_t Size)
{
	char* buf = (char*)ExAllocatePoolWithTag(NonPagedPoolNx, Size, 'AAAA');
	for (int i = 0; i <= Size && buf; i++)
		buf[i] = ' ';
	return STATUS_SUCCESS;
}

NTSTATUS TougherAlloc(size_t Size)
{
	char* buf = (char*)ExAllocatePoolWithTag(NonPagedPoolNx, Size, 'AAAA');
	for (int i = 0; i <= Size && buf; i++)
		buf[i] = 0;
	return STATUS_SUCCESS;
}

NTSTATUS IrpDeviceIoCtlHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
	ULONG IoControlCode = 0;
	PIO_STACK_LOCATION IrpSp = NULL;
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG OutputBytes = 0;

	UNREFERENCED_PARAMETER(DeviceObject);

	IrpSp = IoGetCurrentIrpStackLocation(Irp);
	IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;

	if (IrpSp) {
		switch (IoControlCode) {
		case IOCTL_ALLOC:
			Status = Alloc(*(size_t*)Irp->AssociatedIrp.SystemBuffer);
			break;
		case IOCTL_TOUGHER_ALLOC:
			Status = TougherAlloc(*(size_t*)Irp->AssociatedIrp.SystemBuffer);
			break;
		default:
			Status = STATUS_NOT_SUPPORTED;
			break;
		}
	}

	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = OutputBytes;

	// Complete the request
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}

NTSTATUS IrpCreateCloseHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(DeviceObject);

	// Complete the request
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS IrpNotImplementedHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

	UNREFERENCED_PARAMETER(DeviceObject);

	// Complete the request
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_NOT_SUPPORTED;
}

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING DosDeviceName = { 0 };

	PAGED_CODE();

	RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\Overfl0w");

	// Delete the symbolic link
	IoDeleteSymbolicLink(&DosDeviceName);

	// Delete the device
	IoDeleteDevice(DriverObject->DeviceObject);
}