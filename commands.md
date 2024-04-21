HEN-V Commands
==============

* Payloads send/receive commands by writing/reading to socket fd 3.
* Applications send/receive commands by using `sceAppMessagingSendMsg`/`sceAppMessagingReceiveMsg`.


Command Header
--------------

* All commands sent from a payload **MUST** have the follow header.
  This header **must NOT** be present when sent from an application.

```c
enum CommandType {
    HENV_MSG_TYPE_REGISTER_PREFIX_HANDLER = 0x1000000,
    HENV_MSG_TYPE_UNREGISTER_PREFIX_HANDLER = 0x1000001,
    HENV_MSG_TYPE_REGISTER_LAUNCH_LISTENER = 0x1000002,
	HENV_MSG_TYPE_UNREGISTER_LAUNCH_LISTENER = 0x1000003,
    HENV_MSG_TYPE_APP_LAUNCHED = 0x1000004, // receive only
    HENV_MSG_TYPE_KILL = 0x1000005,
    HENV_MSG_TYPE_GET_PAYLOAD_NUMBER = 0x1000006 // payload only
};

struct PayloadCommandHeader {
    int pid; // getpid()
    enum CommandType type;
    uint32_t message_size;
    uint8_t message[message_size]; // per command struct
};

struct PayloadResponseHeader {
    enum CommandType type;
    uint32_t message_size;
    uint8_t message[message_size]; // per command struct
};
```

* Unless otherwise specified, responses will be in the following format.

```c
struct CommandResponse {
    uint32_t length; // 0 no error message
    char error[length]; // NULL terminator is included
};
```


Registering a Prefix Handler
----------------------------

* There are times where someone may wish to take control of loading an elf for their own purposes.
  This may be achieved by registering a prefix handler with the prefix being the first 4 letters of
  the title id.
* Note: A prefix handler will have 4 seconds, chosen by fair dice roll, to attach to the provided
  pid using ptrace. Failure to do so within this time limit will result in the process dying.
* A registered prefix handler **will not** be notified when the new process is `eboot.bin`.

```c
struct PrefixHandlerCommand {
    char prefix[4];
};
```


Unregistering a Prefix Handler
------------------------------

* A registered prefix handler may only unregister itself.
* It is the handlers responsibility to ensure it is unregistered.
  A *best effort* attempt will be made to remove handlers that have died.

```c
struct UnregisterPrefixHandlerCommand {
    char prefix[4];
};
```


Registering a Launch Listener
-----------------------------

* An application or payload may request to be notified every time a new process
  is created by `SysCore`.
* Only the header is required, if applicable, for this command.


Unregistering a Launch Listener
-------------------------------

* It is the listeners responsibility to ensure it is unregistered.
  A *best effort* attempt will be made to remove listeners that have died.
* Only the header is required, if applicable, for this command.


Application/Process Launched Notification
-----------------------------------------

* The notification sent to a registered prefix handler when a process is created containing
  the prefix in the titleid, or a registered launch listener, is the single 32-bit pid
  of the new process.


Kill Command
------------

* This command will cause HEN-V to panic and exit.
* Doing this will cause all payloads to be terminated as well.
* This command has not been tested because nobody would want to do this intentionally.


Get Payload Number
------------------

* This command is for requesting the payload number of sender.
* This command may only be sent by a payload. If sent by an application
  the response will contain an error message.
* Only the header is required for this command.

```c
struct PayloadNumberResponse {
    int16_t num;
    // optional error only present if num is -1
    struct CommandResponse error;
};
```



Examples
========


Application Example
-------------------

```c
#define MESSAGE_BUFFER_SIZE 8192

typedef struct app_message {
    uint32_t sender;
    uint32_t msgType;
    uint8_t message[MESSAGE_BUFFER_SIZE]; // this stupidity is not my fault
    uint64_t message_size;
    uint64_t timestamp; // format unknown
} app_message_t;

// provided in libSceSystemService.sprx
extern uint32_t sceAppMessagingSendMsg(uint32_t appId, uint32_t msgType, const void *msg, size_t msgLength, uint32_t flags);
extern int sceAppMessagingReceiveMsg(app_message_t *msg);
extern uint32_t sceSystemServiceGetAppId(const char *titleid);

static app_message_t gMsg;

int main() {
    const uint32_t henv = sceSystemServiceGetAppId("HENV00000");
    if ((int)henv <= 0) {
        printf("failed to get HEN-V appid: 0x%08x\n", henv);
        return 0;
    }

    const char cmd[] = {'B', 'R', 'E', 'W'};

    uint32_t err = sceAppMessagingSendMsg(henv, HENV_MSG_TYPE_REGISTER_PREFIX_HANDLER, &cmd, sizeof(cmd), 0);
    if (err != 0) {
        return 0;
    }

    err = sceAppMessagingReceiveMsg(&gMsg);
    if (err != 0) {
        return 0;
    }

    if (gMsg.msgType != HENV_MSG_TYPE_REGISTER_PREFIX_HANDLER) {
        printf("unexpected msg type 0x%08x\n", gMsg.msgType);
        return 0;
    }

    if (gMsg.message_size != sizeof(cmd)) {
        puts((char*)gMsg.message + sizeof(uint32_t));
        return 0;
    }

    err = sceAppMessagingReceiveMsg(&gMsg);
    printf("sceAppMessagingReceiveMsg returned 0x%08x\n", err);
    if (err != 0) {
        return 0;
    }

    if (gMsg.msgType != HENV_MSG_TYPE_APP_LAUNCHED) {
        printf("unexpected msg type 0x%08x\n", gMsg.msgType);
        return 0;
    }

    printf("notified of new new process %d\n", *(int *)gMsg.message);

    // since we are done, done attach with ptrace and let it exit automatically
    // FIXME: unregister yourself, I'm lazy and this is an example

    return 0;
}
```


Payload Example
-------------------

```c
// not provided by standard headers :(
extern void *malloc(size_t);
extern void free(void*);

void payload_main(struct payload_args *args) {
    (void) args;

    const int pid = getpid();
    const int henv = 3;

    struct PayloadCommandHeader hdr = {
        .pid = pid,
        .type = HENV_MSG_TYPE_GET_PAYLOAD_NUMBER,
        .message_size = 0
    };

    if (_write(henv, &hdr, sizeof(hdr)) < 0) {
        perror("_write failed");
        return;
    }

    int16_t num = -1;

    if (_read(henv, &num, sizeof(num)) < 0) {
        perror("_read failed");
        return;
    }

    if (num == -1) {
        uint32_t len = 0;
        if (_read(henv, &len, sizeof(len)) < 0) {
            perror("_read failed");
            return;
        }
        if (len == 0) {
            return;
        }
        char *error = malloc(len);
        if (error == NULL) {
            // unreachable
            perror("malloc failed");
        }
        if (_read(henv, error, len) < 0) {
            free(error);
            perror("_read failed");
            return;
        }
        puts(error);
        return;
    }

    printf("payload number: %d\n", num);
}
```
