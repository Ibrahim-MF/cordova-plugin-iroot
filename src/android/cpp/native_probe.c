#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>

/*
 * native_probe.c
 *
 * Authoritative detection engine. ALL filesystem access here goes through raw
 * syscalls (openat / read / faccessat / close) instead of libc fopen/open or
 * the Java java.io.File / Runtime.exec APIs.
 *
 * This is deliberate: the bypass tooling (ROOTER-Mf.js and similar) hooks:
 *   - java.io.File.exists / canExecute
 *   - java.lang.Runtime.exec / ProcessBuilder
 *   - libc "fopen" and "system"
 *   - java.io.BufferedReader.readLine
 *   - android.os.SystemProperties.get and Build.* fields
 *   - android.app.ApplicationPackageManager.*
 *
 * None of those hooks intercept the openat/read/faccessat syscalls used below,
 * so this layer keeps reporting the truth even when the entire Java/libc layer
 * has been neutralized.
 */

static int g_ptrace_self_attach_failed = 0;

static int sys_open_ro(const char *path) {
    return (int) syscall(SYS_openat, AT_FDCWD, path, O_RDONLY, 0);
}

static int sys_faccess(const char *path) {
    return (int) syscall(SYS_faccessat, AT_FDCWD, path, F_OK, 0);
}

static void append_code(char *dest, size_t dest_size, const char *code) {
    size_t curr = strlen(dest);
    size_t code_len = strlen(code);
    if (curr + code_len + 2 >= dest_size) {
        return;
    }
    if (curr > 0) {
        dest[curr] = ',';
        dest[curr + 1] = '\0';
    }
    strncat(dest, code, dest_size - strlen(dest) - 1);
}

static int buffer_has_any(const char *buf, const char **needles, size_t needles_count) {
    size_t i;
    for (i = 0; i < needles_count; i++) {
        if (strstr(buf, needles[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

/* Read a file via raw syscalls and look for any of the given markers. */
static int scan_file_for_markers(const char *path, const char **markers, size_t markers_count) {
    int fd = sys_open_ro(path);
    if (fd < 0) {
        return 0;
    }

    char buf[4096];
    ssize_t n;
    int hit = 0;
    while ((n = (ssize_t) syscall(SYS_read, fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = '\0';
        if (buffer_has_any(buf, markers, markers_count)) {
            hit = 1;
            break;
        }
    }

    syscall(SYS_close, fd);
    return hit;
}

/* Return 1 if any path in the list is accessible (faccessat F_OK). */
static int any_path_exists(const char **paths, size_t count) {
    size_t i;
    for (i = 0; i < count; i++) {
        if (sys_faccess(paths[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

/* ----------------------------------------------------------------------- */
/* Frida / hooking                                                          */
/* ----------------------------------------------------------------------- */

static int scan_maps_for_frida(void) {
    const char *markers[] = {
        "frida",
        "gum-js",
        "gmain",
        "linjector",
        "frida-agent",
        "frida-gadget",
        "libfrida",
        "libgum"
    };
    return scan_file_for_markers("/proc/self/maps", markers, sizeof(markers) / sizeof(markers[0]));
}

static int check_tracer_pid(void) {
    int fd = sys_open_ro("/proc/self/status");
    if (fd < 0) {
        return 0;
    }

    char buf[4096];
    ssize_t n = (ssize_t) syscall(SYS_read, fd, buf, sizeof(buf) - 1);
    syscall(SYS_close, fd);
    if (n <= 0) {
        return 0;
    }

    buf[n] = '\0';
    char *p = strstr(buf, "TracerPid:");
    if (p == NULL) {
        return 0;
    }

    int tracer = 0;
    sscanf(p + 10, "%d", &tracer);
    return tracer != 0;
}

/* ----------------------------------------------------------------------- */
/* Root: su binaries, magisk, KernelSU, mount anomalies                    */
/* ----------------------------------------------------------------------- */

static int check_su_binaries(void) {
    const char *paths[] = {
        "/system/bin/su",
        "/system/xbin/su",
        "/system/sbin/su",
        "/sbin/su",
        "/su/bin/su",
        "/vendor/bin/su",
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
        "/system/bin/.ext/su",
        "/system/xbin/mu",
        "/system/xbin/daemonsu",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/system/xbin/busybox",
        "/system/bin/busybox",
        "/data/local/xbin/busybox",
        "/system/app/Superuser.apk",
        "/system/app/SuperSU.apk",
        "/system/app/SuperSU/SuperSU.apk"
    };
    return any_path_exists(paths, sizeof(paths) / sizeof(paths[0]));
}

static int check_magisk(void) {
    const char *paths[] = {
        "/sbin/.magisk",
        "/sbin/magisk",
        "/data/adb/magisk",
        "/data/adb/magisk.db",
        "/data/adb/modules",
        "/data/adb/post-fs-data.d",
        "/data/adb/service.d",
        "/cache/.disable_magisk",
        "/data/data/com.topjohnwu.magisk"
    };
    if (any_path_exists(paths, sizeof(paths) / sizeof(paths[0]))) {
        return 1;
    }

    const char *markers[] = {"magisk", "core/mirror", "core/img"};
    return scan_file_for_markers("/proc/self/mountinfo", markers, sizeof(markers) / sizeof(markers[0]));
}

static int check_kernelsu(void) {
    const char *paths[] = {
        "/data/adb/ksu",
        "/data/adb/ksud",
        "/data/adb/KernelSU",
        "/data/adb/modules/zygisksu",
        "/data/adb/modules/kernelsu"
    };
    if (any_path_exists(paths, sizeof(paths) / sizeof(paths[0]))) {
        return 1;
    }

    const char *markers[] = {"KSU", "kernelsu", "zygisksu", "shamiko"};
    return scan_file_for_markers("/proc/self/mountinfo", markers, sizeof(markers) / sizeof(markers[0]));
}

static int check_mountinfo_anomaly(void) {
    const char *markers[] = {"magisk", "zygisk", "shamiko", "kernelsu", "KSU", "/data/adb"};
    return scan_file_for_markers("/proc/self/mountinfo", markers, sizeof(markers) / sizeof(markers[0]));
}

/* ----------------------------------------------------------------------- */
/* Emulator: device files + /proc reads (Build-independent)                */
/* ----------------------------------------------------------------------- */

static int check_emulator_files(void) {
    const char *paths[] = {
        "/dev/socket/qemud",
        "/dev/qemu_pipe",
        "/dev/goldfish_pipe",
        "/dev/goldfish_sync",
        "/sys/qemu_trace",
        "/system/bin/qemu-props",
        "/system/lib/libc_malloc_debug_qemu.so",
        "/system/lib64/libc_malloc_debug_qemu.so",
        "/dev/socket/genyd",
        "/dev/socket/baseband_genyd",
        "/system/bin/microvirtd",
        "/system/bin/nox-prop",
        "/system/bin/ttVM-prop",
        "/system/bin/droid4x-prop",
        "/system/lib/libdroid4x.so",
        "/system/bin/windroyed",
        "/system/bin/microvirt-prop",
        "/data/.bluestacks.prop",
        "/system/bin/ldinit",
        "/system/bin/ldmountsvc"
    };
    return any_path_exists(paths, sizeof(paths) / sizeof(paths[0]));
}

static int check_emulator_cpuinfo(void) {
    const char *markers[] = {"Goldfish", "goldfish", "ranchu", "vbox", "VirtualBox", "hypervisor"};
    return scan_file_for_markers("/proc/cpuinfo", markers, sizeof(markers) / sizeof(markers[0]));
}

static int check_emulator_drivers(void) {
    const char *markers[] = {"goldfish"};
    return scan_file_for_markers("/proc/tty/drivers", markers, sizeof(markers) / sizeof(markers[0]));
}

/* ----------------------------------------------------------------------- */
/* JNI entry points                                                        */
/* ----------------------------------------------------------------------- */

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) vm;
    (void) reserved;

    /*
     * Best-effort self-attach lock. A process can have a single tracer; if this
     * succeeds, a later debugger/frida attach fails. If it fails AND TracerPid
     * is already set, we surface that through nativeScan().
     */
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
        g_ptrace_self_attach_failed = 1;
    }
    return JNI_VERSION_1_6;
}

JNIEXPORT jstring JNICALL
Java_de_cyberkatze_iroot_FridaDetector_nativeScan(JNIEnv *env, jclass clazz) {
    (void) clazz;

    char result[1024];
    result[0] = '\0';

    if (scan_maps_for_frida()) {
        append_code(result, sizeof(result), "HOOK_FRIDA_MAPS");
    }
    if (check_tracer_pid()) {
        append_code(result, sizeof(result), "DEBUGGER_TRACERPID");
    }
    if (g_ptrace_self_attach_failed && check_tracer_pid()) {
        append_code(result, sizeof(result), "DEBUGGER_PTRACE_SELF");
    }

    return (*env)->NewStringUTF(env, result);
}

JNIEXPORT jstring JNICALL
Java_de_cyberkatze_iroot_RootHiderDetector_nativeRootScan(JNIEnv *env, jclass clazz) {
    (void) clazz;

    char result[512];
    result[0] = '\0';

    if (check_su_binaries()) {
        append_code(result, sizeof(result), "ROOT_SU_BINARY");
    }
    if (check_magisk()) {
        append_code(result, sizeof(result), "ROOT_MAGISK");
    }
    if (check_kernelsu()) {
        append_code(result, sizeof(result), "ROOT_KERNELSU");
    }
    if (check_mountinfo_anomaly()) {
        append_code(result, sizeof(result), "ROOT_MOUNTINFO_ANOMALY");
    }

    return (*env)->NewStringUTF(env, result);
}

JNIEXPORT jstring JNICALL
Java_de_cyberkatze_iroot_EmulatorDetector_nativeEmulatorScan(JNIEnv *env, jclass clazz) {
    (void) clazz;

    char result[256];
    result[0] = '\0';

    if (check_emulator_files()) {
        append_code(result, sizeof(result), "EMULATOR_QEMU_FILES");
    }
    if (check_emulator_cpuinfo()) {
        append_code(result, sizeof(result), "EMULATOR_CPUINFO");
    }
    if (check_emulator_drivers()) {
        append_code(result, sizeof(result), "EMULATOR_DRIVERS");
    }

    return (*env)->NewStringUTF(env, result);
}
