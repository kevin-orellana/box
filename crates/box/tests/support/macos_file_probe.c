#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int operation(const char *name, const char *from, const char *to) {
    if (!strcmp(name, "write-twice")) {
        if (operation("write", from, to) != 0) return -1;
        errno = 0;
        int result = operation("write", from, to);
        int error = errno;
        printf("SECOND_WRITE_RESULT=%d ERRNO=%d\n", result, error);
        if (result < 0 && (error == EACCES || error == EPERM)) return 0;
        errno = EINVAL;
        return -1;
    }
    if (!strcmp(name, "create")) {
        int fd = open(from, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0) return -1;
        close(fd);
        return 0;
    }
    if (!strcmp(name, "write") || !strcmp(name, "append")) {
        int fd = open(from, O_WRONLY | (!strcmp(name, "append") ? O_APPEND : 0));
        if (fd < 0) return -1;
        int result = write(fd, "changed", 7) == 7 ? 0 : -1;
        int error = errno;
        close(fd);
        errno = error;
        return result;
    }
    if (!strcmp(name, "read")) {
        int fd = open(from, O_RDONLY);
        if (fd < 0) return -1;
        close(fd);
        return 0;
    }
    if (!strcmp(name, "event-only")) {
        int fd = open(from, O_EVTONLY | O_CLOEXEC);
        if (fd < 0) return -1;
        char byte;
        int result = (int)read(fd, &byte, 1);
        int error = errno;
        errno = 0;
        int written = (int)write(fd, "x", 1);
        int write_error = errno;
        close(fd);
        printf("EVENT_ONLY_READ=%d ERRNO=%d\n", result, error);
        printf("EVENT_ONLY_WRITE=%d ERRNO=%d\n", written, write_error);
        if (result == 1 && written == -1 && write_error == EBADF) return 0;
        errno = EINVAL;
        return -1;
    }
    if (!strcmp(name, "exec-only")) {
        int fd = open(from, O_EXEC | O_CLOEXEC | O_NOCTTY | O_NONBLOCK);
        if (fd < 0) return -1;
        char byte;
        errno = 0;
        int result = (int)read(fd, &byte, 1);
        int error = errno;
        errno = 0;
        int written = (int)write(fd, "x", 1);
        int write_error = errno;
        close(fd);
        printf("EXEC_ONLY_READ=%d ERRNO=%d\n", result, error);
        printf("EXEC_ONLY_WRITE=%d ERRNO=%d\n", written, write_error);
        if (result == -1 && error == EBADF && written == -1 && write_error == EBADF) return 0;
        errno = EINVAL;
        return -1;
    }
    if (!strcmp(name, "truncate")) return truncate(from, 0);
    if (!strcmp(name, "unlink")) return unlink(from);
    if (!strcmp(name, "mkdir")) return mkdir(from, 0700);
    if (!strcmp(name, "rmdir")) return rmdir(from);
    if (!strcmp(name, "symlink")) return symlink(from, to);
    if (!strcmp(name, "rename")) return rename(from, to);
    errno = EINVAL;
    return -1;
}

int main(int argc, char **argv) {
    if (argc != 6) return 90;
    if (!strcmp(argv[5], "child")) {
        pid_t child = fork();
        if (child < 0) return 91;
        if (child > 0) {
            int status;
            if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return 92;
            return WEXITSTATUS(status);
        }
    }
    errno = 0;
    int result = operation(argv[1], argv[2], argv[3]);
    int error = errno;
    printf("NATIVE_RESULT=%d ERRNO=%d\n", result, error);
    if (!strcmp(argv[4], "allow")) return result == 0 ? 0 : 93;
    return result < 0 && (error == EACCES || error == EPERM || error == EROFS) ? 0 : 94;
}
