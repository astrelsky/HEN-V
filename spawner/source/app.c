#include <stdbool.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/_stdint.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/_iovec.h>

#include "app.h"

static const char *json = "{\n"
	"    \"applicationCategoryType\": 33554432,\n"
	"    \"localizedParameters\": {\n"
    "        \"defaultLanguage\": \"en-US\",\n"
    "        \"en-US\": {\n"
    "            \"titleName\": \"HEN-V\"\n"
    "        }\n"
	"    },\n"
	"    \"titleId\": \""APP_TITLE_ID"\"\n"
	"}\n";

typedef struct {
	const void *iov_base;
	size_t iov_length;

	//constexpr NonStupidIovec(const char *str) : iov_base(str), iov_length(__builtin_strlen(str)+1) {}
	//constexpr NonStupidIovec(const char *str, size_t length) : iov_base(str), iov_length(length) {}
} iovec_t;

#define BUILD_IOVEC(str) { .iov_base = (str), .iov_length = __builtin_strlen(str) + 1}

//constexpr NonStupidIovec operator"" _iov(const char *str, unsigned long len) { return {str, len+1}; }

static bool remount(const char *dev, const char *path) {
	iovec_t iov[] = {
		BUILD_IOVEC("fstype"), BUILD_IOVEC("exfatfs"),
		BUILD_IOVEC("fspath"), BUILD_IOVEC(path),
		BUILD_IOVEC("from"), BUILD_IOVEC(dev),
		BUILD_IOVEC("large"), BUILD_IOVEC("yes"),
		BUILD_IOVEC("timezone"), BUILD_IOVEC("static"),
		BUILD_IOVEC("async"), {NULL, 0},
		BUILD_IOVEC("ignoreacl"), {NULL, 0}
	};
	return nmount((struct iovec *)iov, sizeof(iov) / sizeof(iov[0]), MNT_UPDATE) == 0;
}

#define MKDIR_FLAGS 0666

// NOLINTBEGIN(cppcoreguidelines-owning-memory)

static bool copyfile(const char *from, const char *to) {
	struct stat st;
	memset(&st, 0, sizeof(st));
	if (stat(from, &st) == -1) {
		perror("stat failed");
		return false;
	}
	uint8_t *buf = malloc(st.st_size);
	if (buf == NULL) {
		puts("malloc failed");
		return false;
	}
	FILE *fp = fopen(from, "rb");
	if (fp == NULL) {
		perror("open failed");
		free(buf);
		return false;
	}
	fread(buf, 1, st.st_size, fp);
	fclose(fp);
	fp = fopen(to, "wb+");
	if (fp == NULL) {
		perror("open failed");
		free(buf);
		return false;
	}
	fwrite(buf, 1, st.st_size, fp);
	free(buf);
	fclose(fp);
	return true;
}

static bool mkdir_if_necessary(const char *path) {
	if (mkdir(path, MKDIR_FLAGS) == -1) {
		const int err = errno;
		if (err != EEXIST) {
			perror("mkdir failed");
			return false;
		}
	}
	return true;
}

bool make_homebrew_app(void) {
	// REDIS -> NPXS40028
	if (!remount("/dev/ssd0.system_ex", "/system_ex")) {
		perror("makenewapp remount");
		return false;
	}
	if (mkdir("/system_ex/app/"APP_TITLE_ID"", MKDIR_FLAGS) == -1) {
		const int err = errno;
		if (err != EEXIST) {
			perror("makenewapp mkdir /system_ex/app/"APP_TITLE_ID"");
			return false;
		}
		puts(""APP_TITLE_ID" already exists, assuming proper installation");
		return true;
	}
	if (!copyfile("/system_ex/app/NPXS40028/eboot.bin", "/system_ex/app/"APP_TITLE_ID"/eboot.bin")) {
		puts("failed to copy redis eboot.bin");
		return false;
	}
	if (!mkdir_if_necessary("/system_ex/app/"APP_TITLE_ID"/sce_sys")) {
		return false;
	}
	FILE *fp = fopen("/system_ex/app/"APP_TITLE_ID"/sce_sys/param.json", "w+");
	if (fp == NULL) {
		perror("open failed");
		return false;
	}
	fwrite(json, 1, __builtin_strlen(json), fp);
	fclose(fp);
	copyfile("/system_ex/app/"APP_TITLE_ID"/eboot.bin", "/system_ex/app/"APP_TITLE_ID"/payload0.bin");
	copyfile("/system_ex/app/"APP_TITLE_ID"/eboot.bin", "/system_ex/app/"APP_TITLE_ID"/payload1.bin");
	copyfile("/system_ex/app/"APP_TITLE_ID"/eboot.bin", "/system_ex/app/"APP_TITLE_ID"/payload2.bin");
	copyfile("/system_ex/app/"APP_TITLE_ID"/eboot.bin", "/system_ex/app/"APP_TITLE_ID"/payload3.bin");
	copyfile("/system_ex/app/"APP_TITLE_ID"/eboot.bin", "/system_ex/app/"APP_TITLE_ID"/payload4.bin");
	copyfile("/system_ex/app/"APP_TITLE_ID"/eboot.bin", "/system_ex/app/"APP_TITLE_ID"/payload5.bin");
	copyfile("/system_ex/app/"APP_TITLE_ID"/eboot.bin", "/system_ex/app/"APP_TITLE_ID"/payload6.bin");
	copyfile("/system_ex/app/"APP_TITLE_ID"/eboot.bin", "/system_ex/app/"APP_TITLE_ID"/payload7.bin");
	copyfile("/system_ex/app/"APP_TITLE_ID"/eboot.bin", "/system_ex/app/"APP_TITLE_ID"/payload8.bin");
	copyfile("/system_ex/app/"APP_TITLE_ID"/eboot.bin", "/system_ex/app/"APP_TITLE_ID"/payload9.bin");
	copyfile("/system_ex/app/"APP_TITLE_ID"/eboot.bin", "/system_ex/app/"APP_TITLE_ID"/payload10.bin");
	copyfile("/system_ex/app/"APP_TITLE_ID"/eboot.bin", "/system_ex/app/"APP_TITLE_ID"/payload11.bin");
	copyfile("/system_ex/app/"APP_TITLE_ID"/eboot.bin", "/system_ex/app/"APP_TITLE_ID"/payload12.bin");
	copyfile("/system_ex/app/"APP_TITLE_ID"/eboot.bin", "/system_ex/app/"APP_TITLE_ID"/payload13.bin");
	copyfile("/system_ex/app/"APP_TITLE_ID"/eboot.bin", "/system_ex/app/"APP_TITLE_ID"/payload14.bin");
	copyfile("/system_ex/app/"APP_TITLE_ID"/eboot.bin", "/system_ex/app/"APP_TITLE_ID"/payload15.bin");
	return true;
}

// NOLINTEND(cppcoreguidelines-owning-memory)
