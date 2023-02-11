// Injector.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Injector.h"
#include "util_min.h"

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <set>

static void wait_keypress(const char *msg)
{
	puts(msg);
	getchar();
}

static void wait_exit(int code=0, char *msg="\n按Enter以退出程序\n")
{
	wait_keypress(msg);
	exit(code);
}

static void exit_usage(const char *msg)
{
	//                                                          80 column limit --------> \n
	printf("配置错误，请将d3d11.dll复制到目录\n"
	       "然后编辑d3dx.ini中的[Loader]项目\n"
	       "以设置目标程序\n"
	       "\n"
	       "%s", msg);

	wait_exit(EXIT_FAILURE);
}

static bool check_file_description(const char *buf, const char *module_path)
{
	// https://docs.microsoft.com/en-gb/windows/desktop/api/winver/nf-winver-verqueryvaluea
	struct LANGANDCODEPAGE {
		WORD wLanguage;
		WORD wCodePage;
	} *translate_query;
	char id[50];
	char *file_description = "";
	unsigned int query_size, file_desc_size;
	HRESULT hr;
	unsigned i;

	if (!VerQueryValueA(buf, "\\VarFileInfo\\Translation", (void**)&translate_query, &query_size))
		wait_exit(EXIT_FAILURE, "文件信息查询失败\n");

	// Look for the 3DMigoto file description in all language blocks... We
	// could likely skip the loop since we know which language it should be
	// in, but for some reason we included it in the German section which
	// we might want to change, so this way we won't need to adjust this
	// code if we do:
	for (i = 0; i < (query_size / sizeof(struct LANGANDCODEPAGE)); i++) {
		hr = _snprintf_s(id, 50, 50, "\\StringFileInfo\\%04x%04x\\FileDescription",
				translate_query[i].wLanguage,
				translate_query[i].wCodePage);
		if (FAILED(hr))
			wait_exit(EXIT_FAILURE, "文件信息查询遇到问题\n");

		if (!VerQueryValueA(buf, id, (void**)&file_description, &file_desc_size))
			wait_exit(EXIT_FAILURE, "文件信息查询失败\n");

		// Only look for the 3Dmigoto prefix. We've had a whitespace
		// error in the description for all this time that we want to
		// ignore, and we later might want to add other 3DMigoto DLLs
		// like d3d9 and d3d12 with injection support
		if (!strncmp(file_description, "3Dmigoto", 8))
			return true;
	}

	return false;
}

static void check_3dmigoto_version(const char *module_path, const char *ini_section)
{
	VS_FIXEDFILEINFO *query = NULL;
	DWORD pointless_handle = 0;
	unsigned int size;
	char *buf;

	size = GetFileVersionInfoSizeA(module_path, &pointless_handle);
	if (!size)
		wait_exit(EXIT_FAILURE, "版本号检查失败\n");

	buf = new char[size];

	if (!GetFileVersionInfoA(module_path, pointless_handle, size, buf))
		wait_exit(EXIT_FAILURE, "版本信息检查失败\n");

	if (!check_file_description(buf, module_path)) {
		printf("错误: 模块 \"%s\" 不属于加载器\n"
		       "请确认 [Loader] \"module\" 设置正确并且DLL文件正确放置", module_path);
		wait_exit(EXIT_FAILURE);
	}

	if (!VerQueryValueA(buf, "\\", (void**)&query, &size))
		wait_exit(EXIT_FAILURE, "版本号检查失败\n");

	printf("3DMigoto版本：%d.%d.%d\nCompile&translate by Little Gao\n\n",
			query->dwProductVersionMS >> 16,
			query->dwProductVersionMS & 0xffff,
			query->dwProductVersionLS >> 16);

	if (query->dwProductVersionMS <  0x00010003 ||
	    query->dwProductVersionMS == 0x00010003 && query->dwProductVersionLS < 0x000f0000) {
		wait_exit(EXIT_FAILURE, "此版本过旧 - 请使用 1.3.15 或以上版本\n");
	}

	delete [] buf;
}

static bool verify_injection(PROCESSENTRY32 *pe, const wchar_t *module, bool log_name)
{
	HANDLE snapshot;
	MODULEENTRY32 me;
	const wchar_t *basename = wcsrchr(module, '\\');
	bool rc = false;
	static std::set<DWORD> pids;
	wchar_t exe_path[MAX_PATH], mod_path[MAX_PATH];

	if (basename)
		basename++;
	else
		basename = module;

	do {
		snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe->th32ProcessID);
	} while (snapshot == INVALID_HANDLE_VALUE && GetLastError() == ERROR_BAD_LENGTH);
	if (snapshot == INVALID_HANDLE_VALUE) {
		printf("%S (%d): 无法确认3Dmigoto加载是否成功: %d\n",
				pe->szExeFile, pe->th32ProcessID, GetLastError());
		return false;
	}

	me.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(snapshot, &me)) {
		printf("%S (%d): 无法确认3Dmigoto加载是否成功: %d\n",
				pe->szExeFile, pe->th32ProcessID, GetLastError());
		goto out_close;
	}

	// First module is the executable, and this is how we get the full path:
	if (log_name)
		printf("未找到目标程序 (%i): %S\n", pe->th32ProcessID, me.szExePath);
	wcscpy_s(exe_path, MAX_PATH, me.szExePath);

	rc = false;
	while (Module32Next(snapshot, &me)) {
		if (_wcsicmp(me.szModule, basename))
			continue;

		if (!_wcsicmp(me.szExePath, module)) {
			if (!pids.count(pe->th32ProcessID)) {
				printf("%d: 加载成功 :)\n", pe->th32ProcessID);
				pids.insert(pe->th32ProcessID);
			}
			rc = true;
		} else {
			wcscpy_s(mod_path, MAX_PATH, me.szExePath);
			wcsrchr(exe_path, L'\\')[1] = '\0';
			wcsrchr(mod_path, L'\\')[1] = '\0';
			if (!_wcsicmp(exe_path, mod_path)) {
				printf("\n\n\n"
				       "警告: 在游戏目录下找到重复的3Dmigoto程序:\n"
				       "%S\n"
				       "这可能会导致崩溃 - 请移除游戏目录下重复的3Dmigoto程序\n\n\n",
				       me.szExePath);
				wait_exit(EXIT_FAILURE);
			}
		}
	}

out_close:
	CloseHandle(snapshot);
	return rc;
}

static bool check_for_running_target(wchar_t *target, const wchar_t *module)
{
	// https://docs.microsoft.com/en-us/windows/desktop/ToolHelp/taking-a-snapshot-and-viewing-processes
	HANDLE snapshot;
	PROCESSENTRY32 pe;
	bool rc = false;
	wchar_t *basename = wcsrchr(target, '\\');
	static std::set<DWORD> pids;

	if (basename)
		basename++;
	else
		basename = target;

	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		printf("无法确认3Dmigoto加载是否成功: %d\n", GetLastError());
		return false;
	}

	pe.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(snapshot, &pe)) {
		printf("无法确认3Dmigoto加载是否成功: %d\n", GetLastError());
		goto out_close;
	}

	do {
		if (_wcsicmp(pe.szExeFile, basename))
			continue;

		rc = verify_injection(&pe, module, !pids.count(pe.th32ProcessID)) || rc;
		pids.insert(pe.th32ProcessID);
	} while (Process32Next(snapshot, &pe));

out_close:
	CloseHandle(snapshot);
	return rc;
}

static void wait_for_target(const char *target_a, const wchar_t *module_path, bool wait, int delay, bool launched)
{
	wchar_t target_w[MAX_PATH];

	if (!MultiByteToWideChar(CP_UTF8, 0, target_a, -1, target_w, MAX_PATH))
		return;

	for (int seconds = 0; wait || delay == -1; seconds++) {
		if (check_for_running_target(target_w, module_path) && delay != -1)
			break;
		Sleep(1000);

		if (launched && seconds == 3) {
			printf("\n仍在等待游戏启动...\n"
			       "如果游戏未自动启动，请自行运行游戏程序\n"
			       "您也可以修改或移除d3dx.ini中的[Loader] launch= 选项\n\n");
		}
	}

	for (int i = delay; i > 0; i--) {
		printf("加载器将在 %i 后关闭...\r", i);
		Sleep(1000);
		check_for_running_target(target_w, module_path);
	}
	printf("\n");
}

static void elevate_privileges()
{
	DWORD size = sizeof(TOKEN_ELEVATION);
	TOKEN_ELEVATION Elevation;
	wchar_t path[MAX_PATH];
	HANDLE token = NULL;
	int rc;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
		return;

	if (!GetTokenInformation(token, TokenElevation, &Elevation, sizeof(Elevation), &size)) {
		CloseHandle(token);
		return;
	}

	CloseHandle(token);

	if (Elevation.TokenIsElevated)
		return;

	if (!GetModuleFileName(NULL, path, MAX_PATH))
		return;

	CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
	rc = (int)(uintptr_t)ShellExecute(NULL, L"runas", path, NULL, NULL, SW_SHOWNORMAL);
	if (rc > 32) // Success
		exit(0);
	if (rc == SE_ERR_ACCESSDENIED)
		wait_exit(EXIT_FAILURE, "无法获取管理员权限: 拒绝访问\n");
	printf("无法获取管理员权限: %d\n", rc);
	wait_exit(EXIT_FAILURE);
}

wchar_t* deduce_working_directory(wchar_t *setting, wchar_t dir[MAX_PATH])
{
	DWORD ret;
	wchar_t *file_part = NULL;

	ret = GetFullPathName(setting, MAX_PATH, dir, &file_part);
	if (!ret || ret >= MAX_PATH)
		return NULL;

	ret = GetFileAttributes(dir);
	if (ret == INVALID_FILE_ATTRIBUTES)
		return NULL;

	if (!(ret & FILE_ATTRIBUTE_DIRECTORY) && file_part)
		*file_part = '\0';

	printf("工作目录位于: \"%S\"\n", dir);

	return dir;
}

int main()
{
	char *buf, target[MAX_PATH], setting[MAX_PATH], module_path[MAX_PATH];
	wchar_t setting_w[MAX_PATH], working_dir[MAX_PATH], *working_dir_p = NULL;
	DWORD filesize, readsize;
	const char *ini_section;
	wchar_t module_full_path[MAX_PATH];
	int rc = EXIT_FAILURE;
	HANDLE ini_file;
	HMODULE module;
	int hook_proc;
	FARPROC fn;
	HHOOK hook;
	bool launch;

	CreateMutexA(0, FALSE, "Local\\3DMigotoLoader");
	if (GetLastError() == ERROR_ALREADY_EXISTS)
		wait_exit(EXIT_FAILURE, "错误: 检测到另一个3Dmigoto正在运行\n");

	printf("\n-------------------------------3DMigoto Loader------------------------------\n\n");

	ini_file = CreateFile(L"d3dx.ini", GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (ini_file == INVALID_HANDLE_VALUE)
		exit_usage("打开d3dx.ini失败\n");

	filesize = GetFileSize(ini_file, NULL);
	buf = new char[filesize + 1];
	if (!buf)
		wait_exit(EXIT_FAILURE, "无法定位d3dx.ini缓存\n");

	if (!ReadFile(ini_file, buf, filesize, &readsize, 0) || filesize != readsize)
		wait_exit(EXIT_FAILURE, "读取d3dx.ini错误\n");

	CloseHandle(ini_file);

	ini_section = find_ini_section_lite(buf, "loader");
	if (!ini_section)
		exit_usage("d3dx.ini 丢失 [Loader]\n");

	// Check that the target is configured. We don't do anything with this
	// setting from here other than to make sure it is set, because the
	// injection method we are using cannot single out a specific process.
	// Once 3DMigoto has been injected it into a process it will check this
	// value and bail if it is in the wrong one.
	if (!find_ini_setting_lite(ini_section, "target", target, MAX_PATH))
		exit_usage("d3dx.ini [Loader] 丢失必要设置： \"target\" \n");

	if (!find_ini_setting_lite(ini_section, "module", module_path, MAX_PATH))
		exit_usage("d3dx.ini [Loader] 丢失必要设置： \"module\" \n");

	// We've had support for this injection method in 3DMigoto since 1.3.5,
	// however until 1.3.15 it lacked the check in DllMain to bail out of
	// unwanted processes, so that is the first version we consider safe to
	// use for injection and by default we will not allow older DLLs.
	// Disabling this version check can allow the injector to work with
	// third party DLLs that support the same injection method, such as
	// Helix Mod.
	if (find_ini_bool_lite(ini_section, "check_version", true))
		check_3dmigoto_version(module_path, ini_section);

	if (find_ini_bool_lite(ini_section, "require_admin", false))
		elevate_privileges();

	module = LoadLibraryA(module_path);
	if (!module) {
		printf("无法加载3DMigoto \"%s\"\n", module_path);
		wait_exit(EXIT_FAILURE);
	}

	GetModuleFileName(module, module_full_path, MAX_PATH);

	if (find_ini_setting_lite(ini_section, "entry_point", setting, MAX_PATH))
		fn = GetProcAddress(module, setting);
	else
		fn = GetProcAddress(module, "CBTProc");
	if (!fn) {
		wait_exit(EXIT_FAILURE, "此模块不支持注入\n"
			"请确保使用了最新的d3d11.dll\n");
	}

	hook_proc = find_ini_int_lite(ini_section, "hook_proc", WH_CBT);
	hook = SetWindowsHookEx(hook_proc, (HOOKPROC)fn, module, 0);
	if (!hook)
		wait_exit(EXIT_FAILURE, "hook失败\n");

	rc = EXIT_SUCCESS;

	launch = find_ini_setting_lite(ini_section, "launch", setting, MAX_PATH);
	if (launch) {
		printf("3DMigoto 准备就绪, 正在启动 \"%s\"...\n", setting);
		CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

		if (!MultiByteToWideChar(CP_UTF8, 0, setting, -1, setting_w, MAX_PATH))
			wait_exit(EXIT_FAILURE, "启动设置错误\n");

		working_dir_p = deduce_working_directory(setting_w, working_dir);

		ShellExecute(NULL, NULL, setting_w, NULL, working_dir_p, SW_SHOWNORMAL);
	} else {
		printf("3DMigoto准备就绪，请启动游戏\n");
	}

	wait_for_target(target, module_full_path,
			find_ini_bool_lite(ini_section, "wait_for_target", true),
			find_ini_int_lite(ini_section, "delay", 0), launch);

	UnhookWindowsHookEx(hook);
	delete [] buf;

	return rc;
}

