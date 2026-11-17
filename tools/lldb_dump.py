#!/usr/bin/env python3
"""lldb Python 脚本: 附加目标进程, 导出全部可读内存区域为单一镜像。

由 lldb_dump.sh 以
    lldb --batch -o "command script import <this file>" -o "..."
方式驱动, 通过环境变量传入 PID/输出路径。
"""

import os
import lldb


def run(debugger):
    pid = int(os.environ["DUMP_PID"])
    out_path = os.environ["DUMP_OUT"]

    target = debugger.CreateTarget("")
    error = lldb.SBError()
    process = target.AttachToProcessWithID(debugger.GetListener(), pid, error)
    if not error.Success():
        print("attach failed: %s" % error.GetCString())
        return 1

    regions = process.GetMemoryRegions()
    err = lldb.SBError()
    dumped = 0
    total = 0
    skipped_readonly = 0
    with open(out_path, "wb") as out, open(out_path + ".map", "w") as mapf:
        for i in range(regions.GetSize()):
            info = lldb.SBMemoryRegionInfo()
            regions.GetMemoryRegionAtIndex(i, info)
            if not info.IsReadable():
                continue
            # 明文秘密只会出现在可写数据页; 跳过只读代码段/文件映射,
            # 镜像体积可从数 GB 降到几十 MB。
            if not info.IsWritable():
                skipped_readonly += 1
                continue
            start = info.GetRegionBase()
            end = info.GetRegionEnd()
            size = end - start
            data = process.ReadMemory(start, size, err)
            if err.Success() and data is not None:
                out.write(data)
                mapf.write("%#x %#x %d\n" % (start, end, size))
                dumped += 1
                total += len(data)
                err = lldb.SBError()

    process.Detach()
    print("dumped %d writable regions (%d bytes), skipped %d read-only regions"
          % (dumped, total, skipped_readonly))
    return 0


def __lldb_init_module(debugger, _internal_dict):
    # lldb 加载本文件时会调用这个入口
    debugger.SetAsync(False)
    run(debugger)
