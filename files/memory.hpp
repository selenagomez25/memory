#ifndef INCLUDE_MEMORY_HPP
#define INCLUDE_MEMORY_HPP

#pragma once

#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>
#include <string_view>
#include <memory>

class Memory
{
private:
    std::uintptr_t procId = 0;

public:
    HANDLE processHandle = nullptr;

    Memory(const std::wstring_view processName) noexcept
    {
        PROCESSENTRY32W entry = { sizeof(PROCESSENTRY32W) };
        const auto procSnap = std::unique_ptr<void, decltype(&CloseHandle)>(
            CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), CloseHandle);

        if (Process32FirstW(procSnap.get(), &entry)) {
            do {
                if (processName == entry.szExeFile) {
                    procId = entry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(procSnap.get(), &entry));
        }

        if (procId)
            processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procId);
    }

    ~Memory()
    {
        if (processHandle)
            CloseHandle(processHandle);
    }

    const std::uintptr_t GetModuleAddress(const std::wstring_view moduleName) const noexcept
    {
        MODULEENTRY32W entry = { sizeof(MODULEENTRY32W) };
        const auto modSnap = std::unique_ptr<void, decltype(&CloseHandle)>(
            CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId), CloseHandle);

        if (Module32FirstW(modSnap.get(), &entry)) {
            do {
                if (moduleName == entry.szModule) {
                    return reinterpret_cast<std::uintptr_t>(entry.modBaseAddr);
                }
            } while (Module32NextW(modSnap.get(), &entry));
        }
        return 0;
    }

    template <typename T>
    constexpr const T Read(const std::uintptr_t& address) const noexcept
    {
        T value = {};
        ReadProcessMemory(processHandle, reinterpret_cast<const void*>(address), &value, sizeof(T), NULL);
        return value;
    }

    template <typename T>
    constexpr void Write(const std::uintptr_t& address, const T& value) const noexcept
    {
        WriteProcessMemory(processHandle, reinterpret_cast<void*>(address), &value, sizeof(T), NULL);
    }

    LPVOID AllocateMemory(SIZE_T size, DWORD allocationType = MEM_COMMIT | MEM_RESERVE, DWORD protect = PAGE_READWRITE) const noexcept
    {
        return VirtualAllocEx(processHandle, nullptr, size, allocationType, protect);
    }

    BOOL FreeMemory(LPVOID address, SIZE_T size, DWORD freeType = MEM_RELEASE) const noexcept
    {
        return VirtualFreeEx(processHandle, address, size, freeType);
    }
};

#endif // INCLUDE_MEMORY_HPP
