/**
 *
 * JVM Operand Stack Viewer
 *
 * Copyright (c) 2015 ReWolf
 * http://blog.rewolf.pl/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <Windows.h>
#include <WindowsX.h>
#include <TlHelp32.h>
#include <cstdio>
#include <functional>
#include "resource.h"

static const size_t maxLBStringSize = 0x100;

#define DEFAULT_TIMER_INTERVAL 1000
#define DEFAULT_TIMER_INTERVAL_WSTR L"1000"
#define DEFAULT_TIMER_ID 666

#ifndef _WIN64
#	define BITMASK 3
#else
#	define BITMASK 7
#endif

#pragma pack(push, 1)
struct JVMJITCode
{
	DWORD_PTR unk01;							// x64: 4; x86: 2
	DWORD_PTR unk02;							// 1
	DWORD_PTR jvm_offset_BufferBlobVtable;
	DWORD_PTR jvm_offset_flush_icache_stub;
	DWORD unk_tab01[5];
	DWORD unk_ffffffff;							// -1
};
#pragma pack(pop)

class SmartHandle
{
	public:
		SmartHandle(HANDLE h) : m_handle(h) { }
		~SmartHandle() { if (INVALID_HANDLE_VALUE != m_handle) CloseHandle(m_handle); }

		operator HANDLE() const { return m_handle; }
		
	private:
		const HANDLE m_handle;
};

DWORD_PTR getThreadStackPtr(DWORD tid)
{
	SmartHandle hTh = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
	DWORD_PTR trsp = 0;
	if ((0 != hTh) && (GetCurrentThreadId() != tid))
	{
		SuspendThread(hTh);
		CONTEXT ctx = { 0 };
		ctx.ContextFlags = CONTEXT_ALL;
		GetThreadContext(hTh, &ctx);
		ResumeThread(hTh);
#ifndef _WIN64
		trsp = ctx.Esp;
#else
		trsp = ctx.Rsp;
#endif
	}
	return trsp;
}

DWORD getHexFromLB(HWND hWnd)
{
	int csel = ListBox_GetCurSel(hWnd);
	if (LB_ERR == csel)
		return (DWORD)-1;

	wchar_t tstr[maxLBStringSize];
	if (LB_ERR == ListBox_GetText(hWnd, csel, tstr))
		return (DWORD)-1;

	DWORD ret = (DWORD)-1;
	swscanf_s(tstr, L"%08X", &ret);
	return ret;
}

DWORD_PTR getHexFromLB2(HWND hWnd)
{
	int csel = ListBox_GetCurSel(hWnd);
	if (LB_ERR == csel)
		return (DWORD_PTR)-1;

	wchar_t tstr[maxLBStringSize];
	if (LB_ERR == ListBox_GetText(hWnd, csel, tstr))
		return (DWORD_PTR)-1;

	DWORD_PTR ret = (DWORD_PTR)-1;
	DWORD_PTR ret2 = (DWORD_PTR)-1;
	swscanf_s(tstr, L"%p: %p", &ret, &ret2);
	return ret2;
}

DWORD getCurrentPID(HWND HWnd)
{
	return getHexFromLB(GetDlgItem(HWnd, LB_PROCESSES));
}

DWORD getCurrentTID(HWND HWnd)
{
	return getHexFromLB(GetDlgItem(HWnd, LB_THREADS));
}

int VooDooCheckStandard(DWORD_PTR* stack, int i, DWORD_PTR ctx_rsp, HANDLE hProc)
{
	if ((0 != i) && (stack[i] == ctx_rsp + i*sizeof(DWORD_PTR)))
	{
		for (int j = i - 1; j > 0; j--)
		{
			MEMORY_BASIC_INFORMATION mbi;
			VirtualQueryEx(hProc, (LPCVOID)stack[j], &mbi, sizeof(mbi));
			if ((PAGE_EXECUTE_READWRITE == mbi.Protect) &&
				(MEM_PRIVATE == mbi.Type))
			{
				JVMJITCode jit = { 0 };
				SIZE_T dummy;
				ReadProcessMemory(hProc, mbi.AllocationBase, &jit, sizeof(jit), &dummy);
				if (jit.unk_ffffffff == -1)
				{
					return j + 1;
				}
			}
		}
	}
	return -1;
}

int VooDooCheckMonitor(DWORD_PTR* stack, int i, DWORD_PTR ctx_rsp, HANDLE hProc)
{
	const int maxMonitorDepth = min(i, 20) / 2;
	if ((i > 2) && 
		(stack[i] < ctx_rsp + i*sizeof(DWORD_PTR)) &&
		(stack[i] >= ctx_rsp + (i - maxMonitorDepth)*sizeof(DWORD_PTR)) &&
		((stack[i] & BITMASK) == 0) &&
		((ctx_rsp + i*sizeof(DWORD_PTR) - stack[i]) % (2*sizeof(DWORD_PTR)) == 0))
	{
		// Check only first monitor, maybe it's sufficient.
		DWORD_PTR monitorAddr = 0;
		SIZE_T dummy = 0;
		ReadProcessMemory(hProc, (LPCVOID)stack[i - 1], &monitorAddr, sizeof(monitorAddr), &dummy);
		if ((monitorAddr == ctx_rsp + (i - 2)*sizeof(DWORD_PTR)) ||
			(0 == stack[i - 1]))
		{
			for (int j = i - 3; j > 0; j--)
			{
				MEMORY_BASIC_INFORMATION mbi;
				VirtualQueryEx(hProc, (LPCVOID)stack[j], &mbi, sizeof(mbi));
				if ((PAGE_EXECUTE_READWRITE == mbi.Protect) &&
					(MEM_PRIVATE == mbi.Type))
				{
					JVMJITCode jit = { 0 };
					SIZE_T dummy;
					ReadProcessMemory(hProc, mbi.AllocationBase, &jit, sizeof(jit), &dummy);
					if (jit.unk_ffffffff == -1)
					{
						return j + 1;
					}
				}
			}
		}
	}
	return -1;
}

int doJVMOpStackVooDoo(DWORD_PTR* stack, size_t cnt, DWORD_PTR ctx_rsp, HANDLE hProc, std::function<void(size_t, DWORD_PTR)> callback_on_each_entry)
{
	int retStandard = -1;
	int retMonitor = -1;
	for (size_t i = 0; i < cnt; i++)
	{
		if (-1 == retStandard)
		{
			retStandard = VooDooCheckStandard(stack, (int)i, ctx_rsp, hProc);

			if (-1 == retMonitor)
				retMonitor = VooDooCheckMonitor(stack, (int)i, ctx_rsp, hProc);
		}

		callback_on_each_entry(i, stack[i]);
	}
	return (-1 != retStandard) ? retStandard : retMonitor;
}

void refreshMemory_internal(HWND hWnd, DWORD_PTR addr, DWORD lbID)
{
	DWORD pid = getCurrentPID(hWnd);
	if ((DWORD)-1 == pid)
		return;

	HWND lbMem = GetDlgItem(hWnd, lbID);
	SendMessage(lbMem, WM_SETREDRAW, FALSE, 0);
	ListBox_ResetContent(lbMem);

	SmartHandle hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (INVALID_HANDLE_VALUE != hProc)
	{
		BYTE mem[0x1000];
		SIZE_T dummy = 0;
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
		size_t readSize = (DWORD_PTR)mbi.BaseAddress + mbi.RegionSize - addr;
		readSize = (readSize > sizeof(mem)) ? sizeof(mem) : readSize;
		if (ReadProcessMemory(hProc, (LPCVOID)addr, mem, readSize, &dummy))
		{
			wchar_t tstr[maxLBStringSize];
			swprintf_s(tstr, L"%08X %08X", mbi.AllocationProtect, mbi.Protect);
			ListBox_AddString(lbMem, tstr);
			for (SIZE_T i = 0; i < dummy; i+=8)
			{
#define CAZ(n) (mem[i + (n)] > 0x1f) ? mem[i + (n)] : '.'
				swprintf_s(tstr, L"%p: %02X %02X %02X %02X %02X %02X %02X %02X | %c%c%c%c%c%c%c%c ", 
					addr + i, mem[i], mem[i + 1], mem[i + 2], mem[i + 3], mem[i + 4], mem[i + 5], mem[i + 6], mem[i + 7],
					CAZ(0), CAZ(1), CAZ(2), CAZ(3), CAZ(4), CAZ(5), CAZ(6), CAZ(7));
#undef CAZ
				ListBox_AddString(lbMem, tstr);
			}
		}
	}

	SendMessage(lbMem, WM_SETREDRAW, TRUE, 0);
}

void refreshMemory2(HWND hWnd)
{
	wchar_t tstr[maxLBStringSize];
	tstr[0] = 0;
	GetDlgItemText(hWnd, EDT_ADDRESS, tstr, maxLBStringSize);
	DWORD_PTR addr = 0;
	swscanf_s(tstr, L"%p", &addr);
	refreshMemory_internal(hWnd, addr, LB_HEXMEM2);
}

void refreshMemory(HWND hWnd)
{
	refreshMemory_internal(hWnd, getHexFromLB2(GetDlgItem(hWnd, LB_STACK)), LB_HEXMEM);
}

void refreshStack(HWND hWnd, int csel = -1, int topIdx = -1)
{
	DWORD tid = getCurrentTID(hWnd);
	DWORD pid = getCurrentPID(hWnd);
	if (((DWORD)-1 == tid) || (GetCurrentThreadId() == tid) || ((DWORD)-1 == pid))
		return;

	HWND lbStack = GetDlgItem(hWnd, LB_STACK);
	SendMessage(lbStack, WM_SETREDRAW, FALSE, 0);
	ListBox_ResetContent(lbStack);

	SmartHandle hTh = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
	if (INVALID_HANDLE_VALUE != hTh)
	{
		SuspendThread(hTh);
		CONTEXT ctx = { 0 };
		ctx.ContextFlags = CONTEXT_ALL;
		GetThreadContext(hTh, &ctx);

		SmartHandle hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (INVALID_HANDLE_VALUE != hProc)
		{
			BYTE mem[0x10000];
			SIZE_T dummy = 0;
			MEMORY_BASIC_INFORMATION mbi = { 0 };
#ifndef _WIN64
			DWORD stackPtr = ctx.Esp;
#else
			DWORD64 stackPtr = ctx.Rsp;
#endif
			VirtualQueryEx(hProc, (LPCVOID)stackPtr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
			size_t readSize = (DWORD_PTR)mbi.BaseAddress + mbi.RegionSize - stackPtr;
			readSize = (readSize > sizeof(mem)) ? sizeof(mem) : readSize;
			bool stackFound = false;
			if (ReadProcessMemory(hProc, (LPCVOID)stackPtr, mem, readSize, &dummy))
			{
				csel = doJVMOpStackVooDoo((DWORD_PTR*)mem, dummy / sizeof(DWORD_PTR), stackPtr, hProc, 
				[&stackPtr, &lbStack](size_t i, DWORD_PTR curV)
				{
					wchar_t tstr[maxLBStringSize];
					swprintf_s(tstr, L"%p: %p", stackPtr + i*sizeof(DWORD_PTR), curV);	
					ListBox_AddString(lbStack, tstr);
				});
				if (-1 != topIdx)
					topIdx = (csel < 0) ? 0 : csel - 0;
			}
		}
		ResumeThread(hTh);
	}

	if (-1 != csel)
	{
		ListBox_SetCurSel(lbStack, csel);
		refreshMemory(hWnd);
	}

	if (-1 != topIdx)
		ListBox_SetTopIndex(lbStack, topIdx);

	SendMessage(lbStack, WM_SETREDRAW, TRUE, 0);
}

bool detectJVMStack(DWORD pid, DWORD_PTR ctx_rsp)
{
	if (0 == ctx_rsp)
		return false;

	SmartHandle hProc = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (INVALID_HANDLE_VALUE != hProc)
	{
		BYTE mem[0x10000];
		SIZE_T dummy = 0;
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		VirtualQueryEx(hProc, (LPCVOID)ctx_rsp, &mbi, sizeof(MEMORY_BASIC_INFORMATION));
		size_t readSize = (DWORD_PTR)mbi.BaseAddress + mbi.RegionSize - ctx_rsp;
		readSize = (readSize > sizeof(mem)) ? sizeof(mem) : readSize;
		if (ReadProcessMemory(hProc, (LPCVOID)ctx_rsp, mem, readSize, &dummy))
		{
			return -1 != doJVMOpStackVooDoo((DWORD_PTR*)mem, dummy / sizeof(DWORD_PTR), ctx_rsp, hProc, [](size_t, DWORD_PTR){});
		}
	}
	return false;
}

void refreshThreads(HWND hWnd)
{
	HWND hLBThreads = GetDlgItem(hWnd, LB_THREADS);
	HWND hLBStack = GetDlgItem(hWnd, LB_STACK);
	HWND hLBMem = GetDlgItem(hWnd, LB_HEXMEM);

	DWORD pid = getCurrentPID(hWnd);
	if ((DWORD)-1 == pid)
	{
		ListBox_ResetContent(hLBThreads);
		ListBox_ResetContent(hLBStack);
		ListBox_ResetContent(hLBMem);
		return;
	}

	SmartHandle hToolHelp = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (INVALID_HANDLE_VALUE == hToolHelp)
		return;

	DWORD ctid = getCurrentTID(hWnd);

	int stackCurSel = ListBox_GetCurSel(hLBStack);
	int stackTopIdx = ListBox_GetTopIndex(hLBStack);
	
	SendMessage(hLBThreads, WM_SETREDRAW, FALSE, 0);
	SendMessage(hLBStack, WM_SETREDRAW, FALSE, 0);
	SendMessage(hLBMem, WM_SETREDRAW, FALSE, 0);

	ListBox_ResetContent(hLBThreads);
	ListBox_ResetContent(hLBStack);
	ListBox_ResetContent(hLBMem);

	THREADENTRY32 thEntry = { 0 };
	thEntry.dwSize = sizeof(thEntry);
	if (Thread32First(hToolHelp, &thEntry))
	{
		do 
		{
			if (pid == thEntry.th32OwnerProcessID)
			{
				DWORD_PTR trsp = getThreadStackPtr(thEntry.th32ThreadID);

				bool show = true;
				if (BST_CHECKED == SendDlgItemMessage(hWnd, CHK_THREADS_ONLY_JVM, BM_GETCHECK, 0, 0))
				{
					if (!detectJVMStack(pid, trsp))
						show = false;
				}

				if (show)
				{
					wchar_t tstr[maxLBStringSize];
					swprintf_s(tstr, L"%08X (%d)", thEntry.th32ThreadID, thEntry.th32ThreadID);
					ListBox_AddString(hLBThreads, tstr);

					if (ctid == thEntry.th32ThreadID)
					{
						ListBox_SetCurSel(hLBThreads, ListBox_GetCount(hLBThreads) - 1);
						refreshStack(hWnd, stackCurSel, stackTopIdx);
					}
				}

			}
		} 
		while (Thread32Next(hToolHelp, &thEntry));
	}

	SendMessage(hLBThreads, WM_SETREDRAW, TRUE, 0);
	SendMessage(hLBStack, WM_SETREDRAW, TRUE, 0);
	SendMessage(hLBMem, WM_SETREDRAW, TRUE, 0);
}

void updateInterval(HWND hWnd)
{
	DWORD v = GetDlgItemInt(hWnd, EDT_INTERVAL, nullptr, FALSE);
	if (0 != v)
		SetTimer(hWnd, DEFAULT_TIMER_ID, v, nullptr);
	else
		SetDlgItemText(hWnd, EDT_INTERVAL, DEFAULT_TIMER_INTERVAL_WSTR);
}

void refreshProcesses(HWND hWnd)
{
	SmartHandle th32 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
	if (INVALID_HANDLE_VALUE == th32)
		return;

	bool onlyJVM = false;
	if (BST_CHECKED == SendDlgItemMessage(hWnd, CHK_PROCESS_ONLY_JVM, BM_GETCHECK, 0, 0))
		onlyJVM = true;

	HWND lbProc = GetDlgItem(hWnd, LB_PROCESSES);
	ListBox_ResetContent(lbProc);

	PROCESSENTRY32 procEntry = { 0 };
	procEntry.dwSize = sizeof(procEntry);
	if (Process32First(th32, &procEntry))
	{
		do 
		{
			bool show = true;
			if (onlyJVM)
			{
				show = false;
				THREADENTRY32 thEnt = { 0 };
				thEnt.dwSize = sizeof(thEnt);
				if (Thread32First(th32, &thEnt))
				{
					do 
					{
						if ((thEnt.th32OwnerProcessID == procEntry.th32ProcessID) && detectJVMStack(procEntry.th32ProcessID, getThreadStackPtr(thEnt.th32ThreadID)))
						{
							show = true;
							break;
						}
					}
					while (Thread32Next(th32, &thEnt));
				}
			}
			if (show)
			{
				wchar_t tstr[maxLBStringSize];
				swprintf_s(tstr, L"%08X (%d) %ws", procEntry.th32ProcessID, procEntry.th32ProcessID, procEntry.szExeFile);
				ListBox_AddString(lbProc, tstr);
			}
		} 
		while (Process32Next(th32, &procEntry));
	}

	refreshThreads(hWnd);
}

void onWMCommand(HWND hWnd, WPARAM wParam, LPARAM lParam)
{
	switch (wParam)
	{
		case MAKELPARAM(CHK_THREADS_ONLY_JVM, 0):
		case MAKELPARAM(LB_PROCESSES, LBN_SELCHANGE): refreshThreads(hWnd); break;
		case MAKELPARAM(LB_THREADS, LBN_SELCHANGE): refreshStack(hWnd, -1, 0); break;
		case MAKELPARAM(LB_STACK, LBN_SELCHANGE): refreshMemory(hWnd); break;
		case MAKELPARAM(CHK_PROCESS_ONLY_JVM, 0):
		case MAKELPARAM(BTN_PROCESS_REFRESH, 0): refreshProcesses(hWnd); break;
		case MAKELPARAM(EDT_ADDRESS, EN_CHANGE): refreshMemory2(hWnd); break;
		case MAKELPARAM(EDT_INTERVAL, EN_CHANGE): updateInterval(hWnd); break;
	}
}

void onWMInitDialog(HWND hWnd)
{
	HGDIOBJ fixedFont = GetStockObject(SYSTEM_FIXED_FONT);
	SendDlgItemMessage(hWnd, LB_HEXMEM, WM_SETFONT, (WPARAM)fixedFont, TRUE);
	SendDlgItemMessage(hWnd, LB_HEXMEM2, WM_SETFONT, (WPARAM)fixedFont, TRUE);
	SendDlgItemMessage(hWnd, LB_STACK, WM_SETFONT, (WPARAM)fixedFont, TRUE);
	SendDlgItemMessage(hWnd, LB_PROCESSES, WM_SETFONT, (WPARAM)fixedFont, TRUE);
	SendDlgItemMessage(hWnd, LB_THREADS, WM_SETFONT, (WPARAM)fixedFont, TRUE);

	SendDlgItemMessage(hWnd, CHK_STACK_AUTO, BM_SETCHECK, BST_CHECKED, 0);
	SendDlgItemMessage(hWnd, CHK_THREADS_ONLY_JVM, BM_SETCHECK, BST_CHECKED, 0);
	SendDlgItemMessage(hWnd, CHK_PROCESS_ONLY_JVM, BM_SETCHECK, BST_CHECKED, 0);

	refreshProcesses(hWnd);
	
	SetDlgItemText(hWnd, EDT_INTERVAL, DEFAULT_TIMER_INTERVAL_WSTR);
	SetTimer(hWnd, DEFAULT_TIMER_ID, DEFAULT_TIMER_INTERVAL, 0);
}

void onWMTimer(HWND hWnd)
{
	if (BST_CHECKED == SendDlgItemMessage(hWnd, CHK_STACK_AUTO, BM_GETCHECK, 0, 0))
	{
		refreshThreads(hWnd);
		refreshMemory2(hWnd);
	}
}

INT_PTR onWMCTLColorListBox(HWND hWnd, WPARAM wParam, LPARAM lParam)
{
	SetBkMode((HDC)wParam, TRANSPARENT);
	SetTextColor((HDC)wParam, RGB(0xC0, 0xC0, 0xC0));
	return (INT_PTR)GetStockObject(BLACK_BRUSH);
}

INT_PTR CALLBACK DialogProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
		case WM_CLOSE: EndDialog(hwndDlg, 0); break;
		case WM_INITDIALOG: onWMInitDialog(hwndDlg); break;
		case WM_COMMAND: onWMCommand(hwndDlg, wParam, lParam); break;
		case WM_TIMER: onWMTimer(hwndDlg); break;
		case WM_CTLCOLORLISTBOX: return onWMCTLColorListBox(hwndDlg, wParam, lParam);
		default: return FALSE;
	}
	return TRUE;
}

int wmain(int argc, wchar_t* argv[])
{
	DialogBoxParam(GetModuleHandle(0), (LPCTSTR)DLG_MAIN, 0, DialogProc, 0);
	return 0;
}
