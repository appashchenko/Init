#include <blkid/blkid.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libcryptsetup.h>
#include <libmount/libmount.h>
#include <limits.h>
#include <selinux/selinux.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <termios.h>
#include <unistd.h>

#define F_TYPE_EQUAL(a, b) (a == (__typeof__(a))b)
#define STATFS_RAMFS_MAGIC 0x858458f6
#define STATFS_TMPFS_MAGIC 0x01021994

const char *CRYPTROOT = "UUID=DISKUUID-HERE-HERE-YOUR-cDISKUUIDYES";
const char *REALROOT = "/dev/mapper/root";
const char *ROOT = "root";
const char *init = "/sbin/init";

static int recursiveRemove(int fd);
static int switchroot(const char *newroot);

int main(int argc, char *argv[]) {
  struct crypt_device *cd;
  struct crypt_active_device cad;
  struct termios old_term, new_term;

  setenv("PATH", "/bin:/usr/bin:/sbin", true);

  if (mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID,
            "mode=0755,size=1024k") != 0) {
    printf("Failed to mount %s: %s\n", "devtmpfs", strerror(errno));
    return -1;
  }

  if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV,
            "hidepid=2") != 0) {
    printf("Failed to mount %s: %s\n", "proc", strerror(errno));
    return -1;
  }

  if (mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NOEXEC | MS_NODEV, "") !=
      0) {
    printf("Failed to mount %s: %s\n", "sysfs", strerror(errno));
    return -1;
  }

  if (mount("none", "/run", "tmpfs", MS_NOSUID | MS_NODEV | MS_RELATIME,
            "mode=0755,size=2048k") != 0) {
    printf("Failed to mount %s: %s\n", "/run", strerror(errno));
    return -1;
  }

  char *device_name = blkid_evaluate_tag(CRYPTROOT, NULL, NULL);
  if (device_name == NULL) {
    printf("Can not find device %s\n", CRYPTROOT);
    return -1;
  }

  if (mkdir("/run/cryptsetup", S_IFDIR) != 0) {
    printf("Failed to create directory %s: %s\n", "/run/cryptsetup",
           strerror(errno));
    return -1;
  }

  if (mkdir("/run/lock", S_IFDIR) != 0) {
    printf("Can not set security context for %s: %s", "/run/lock",
           strerror(errno));
  }

  if (crypt_init(&cd, device_name) < 0) {
    printf("crypt_init() failed for %s: %s\n", device_name, strerror(errno));
    return -1;
  }

  if (crypt_load(cd, CRYPT_LUKS2, NULL) < 0) {
    const char *crypt_device_name = crypt_get_device_name(cd);
    printf("crypt_load() failed on device %s: %s\n", crypt_device_name,
           strerror(errno));
    goto fail;
  }

  printf("Enter password:");

  if (tcgetattr(fileno(stdin), &old_term) != 0) {
    printf("Could not get terminal info: %s\n", strerror(errno));
    goto fail;
  }

  new_term = old_term;
  new_term.c_lflag &= ~ECHO;

  if (tcsetattr(fileno(stdin), TCSAFLUSH, &new_term) != 0) {
    printf("Could not set terminal info: %s\n", strerror(errno));
    goto fail;
  }

  {
    for (int i = 0; i < 4; i++) {
      size_t bufsz = 32;
      char *password = malloc(bufsz);
      int len, ret;

      len = getline(&password, &bufsz, stdin);

      tcsetattr(fileno(stdin), TCSAFLUSH, &old_term);
      ret =
          crypt_activate_by_passphrase(cd, ROOT, CRYPT_ANY_SLOT, password,
                                       len - 1, CRYPT_ACTIVATE_ALLOW_DISCARDS);
      if (getentropy(password, bufsz) < 0) {
        printf("Entropy failed: %s\n", strerror(errno));
      }

      if (getrandom(&len, sizeof(len), 0) < 0) {
        printf("Random failed: %s\n", strerror(errno));
      }

      free(password);

      if (ret == 0) {
        crypt_free(cd);
        goto decrypt_success;
      }
    }
    printf("Device %s activation failed: %s\n", ROOT, strerror(errno));
    goto fail;
  }

decrypt_success:
  if (mount(REALROOT, "/mnt/root", "ext4", MS_LAZYTIME | MS_RDONLY,
            "errors=remount-ro,discard,commit=30") != 0) {
    printf("Failed to mount root device: %s\n", strerror(errno));
    goto fail;
  }

  /*if (mount("/dev", "/mnt/root/dev", NULL, MS_MOVE, NULL) != 0) {
    printf("Failed to move /dev to root device: %s\n", strerror(errno));
    goto fail;
  }*/


  /*if (mount("/run", "/mnt/root/run", NULL, MS_MOVE, NULL) != 0) {
    printf("Failed to move /run to new root: %s\n", strerror(errno));
    goto fail;
  }*/

  if (umount("/proc") < 0) {
    printf("Failed to umount %s: %s\n", "/proc", strerror(errno));
  }

  if (umount("/sys") < 0) {
    printf("Failed to umount %s: %s\n", "/sys", strerror(errno));
  }

  if (umount("/dev") < 0) {
    printf("Failed to umount %s: %s\n", "/dev", strerror(errno));
  }

  if (switchroot("/mnt/root") < 0) {
    printf("Failed to switch root: %s\n", strerror(errno));
    goto fail;
  }

  execv(init, argv);
  return 0;

fail:
  if (crypt_status(cd, ROOT) == CRYPT_ACTIVE) {
    crypt_deactivate(cd, ROOT);
  }
  crypt_free(cd);
  return -1;
}

static int switchroot(const char *newroot) {
  /*  Don't try to unmount the old "/", there's no way to do it. */
  const char *umounts[] = {"/dev", "/proc", "/sys", "/run", NULL};
  int i;
  int cfd = -1;
  struct stat newroot_stat, oldroot_stat, sb;

  if (stat("/", &oldroot_stat) != 0) {
    printf("Stat of %s failed: %s\n", "/", strerror(errno));
    return -1;
  }

  if (stat(newroot, &newroot_stat) != 0) {
    printf("Stat of %s failed: %s\n", newroot, strerror(errno));
    return -1;
  }

  for (i = 0; umounts[i] != NULL; i++) {
    char newmount[PATH_MAX];

    snprintf(newmount, sizeof(newmount), "%s%s", newroot, umounts[i]);

    if ((stat(umounts[i], &sb) == 0) && sb.st_dev == oldroot_stat.st_dev) {
      /* mount point to move seems to be a normal directory or stat failed */
      continue;
    }

    if ((stat(newmount, &sb) != 0) || (sb.st_dev != newroot_stat.st_dev)) {
      /* mount point seems to be mounted already or stat failed */
      umount2(umounts[i], MNT_DETACH);
      continue;
    }

    if (mount(umounts[i], newmount, NULL, MS_MOVE, NULL) < 0) {
      printf("failed to mount moving %s to %s", umounts[i], newmount);
      printf("forcing unmount of %s", umounts[i]);
      umount2(umounts[i], MNT_FORCE);
    }
  }

  if (chdir(newroot)) {
    printf("failed to change directory to %s", newroot);
    return -1;
  }

  cfd = open("/", O_RDONLY);
  if (cfd < 0) {
    printf("cannot open %s", "/");
    goto fail;
  }

  if (mount(newroot, "/", NULL, MS_MOVE, NULL) < 0) {
    printf("failed to mount moving %s to /", newroot);
    goto fail;
  }

  if (chroot(".")) {
    printf("failed to change root");
    goto fail;
  }

  if (chdir("/")) {
    printf("cannot change directory to %s", "/");
    goto fail;
  }

  switch (fork()) {
  case 0: /* child */
  {
    struct statfs stfs;

    if (fstatfs(cfd, &stfs) == 0 &&
        (F_TYPE_EQUAL(stfs.f_type, STATFS_RAMFS_MAGIC) ||
         F_TYPE_EQUAL(stfs.f_type, STATFS_TMPFS_MAGIC)))
      recursiveRemove(cfd);
    else {
      printf("old root filesystem is not an initramfs");
      close(cfd);
    }
    exit(EXIT_SUCCESS);
  }
  case -1: /* error */
    break;

  default: /* parent */
    close(cfd);
    return 0;
  }

fail:
  if (cfd >= 0) {
    close(cfd);
  }
  return -1;
}

static int recursiveRemove(int fd) {
  struct stat rb;
  DIR *dir;
  int rc = -1;
  int dfd;

  dir = fdopendir(fd);
  if (dir == NULL) {
    printf("failed to open directory");
    goto done;
  }

  /* fdopendir() precludes us from continuing to use the input fd */
  dfd = dirfd(dir);
  if (fstat(dfd, &rb)) {
    printf("stat failed");
    goto done;
  }

  while (1) {
    struct dirent *d;
    int isdir = 0;

    errno = 0;
    if (!(d = readdir(dir))) {
      if (errno) {
        printf("failed to read directory");
        goto done;
      }
      break; /* end of directory */
    }

    if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
      continue;
#ifdef _DIRENT_HAVE_D_TYPE
    if (d->d_type == DT_DIR || d->d_type == DT_UNKNOWN)
#endif
    {
      struct stat sb;

      if (fstatat(dfd, d->d_name, &sb, AT_SYMLINK_NOFOLLOW)) {
        printf("stat of %s failed", d->d_name);
        continue;
      }

      /* skip if device is not the same */
      if (sb.st_dev != rb.st_dev) {
        continue;
      }

      /* remove subdirectories */
      if (S_ISDIR(sb.st_mode)) {
        int cfd;

        cfd = openat(dfd, d->d_name, O_RDONLY);
        if (cfd >= 0) {
          recursiveRemove(cfd); /* it closes cfd too */
        }
        isdir = 1;
      }
    }

    if (unlinkat(dfd, d->d_name, isdir ? AT_REMOVEDIR : 0)) {
      printf("failed to unlink %s", d->d_name);
    }
  }

  rc = 0; /* success */
done:
  if (dir) {
    closedir(dir);
  } else {
    close(fd);
  }
  return rc;
}

// vim: ts=2 sw=2 expandtab
