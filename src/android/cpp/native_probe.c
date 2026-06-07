#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <linux/limits.h>

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
        dest[curr++] = ',';
        dest[curr] = '\0';
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

static int scan_root_hider_markers(void) {
    const char *markers[] = {"magisk", "zygisk", "shamiko", "kernelsu", "ksu", "/data/adb"};
    return scan_file_for_markers("/proc/self/mountinfo", markers, sizeof(markers) / sizeof(markers[0]));
}

static int check_kernelsu_paths(void) {
    const char *paths[] = {
        "/data/adb/ksu",
        "/data/adb/ksud",
        "/data/adb/modules/zygisksu",
        "/data/adb/KernelSU",
        "/data/adb/modules/kernelsu"
    };
    size_t i;
    for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        if (sys_faccess(paths[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) vm;
    (void) reserved;

    /*
     * Best-effort self-attach lock. If this fails while TracerPid is non-zero,
     * we surface it as an anti-debug signal through nativeScan().
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

    if (scan_root_hider_markers()) {
        append_code(result, sizeof(result), "ROOT_MOUNTINFO_ANOMALY");
    }
    if (check_kernelsu_paths()) {
        append_code(result, sizeof(result), "ROOT_KERNELSU");
    }

    return (*env)->NewStringUTF(env, result);
}
