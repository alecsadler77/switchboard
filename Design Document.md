# Switchboard: A Technical Specification for a Unix-First Permission System

> [!NOTE]  
> This is a **draft**! More refinement is needed.

**The Linux desktop has lost its way.**

In our pursuit of secure, sandboxed applications, we have constructed a skyscraper to solve a problem that required a garden shed. The current implementation of **XDG Desktop Portals**—the standard mechanism for applications to request permissions like camera access or file selection—is a labyrinth of D-Bus calls, specific backend implementations, and vague error states.

It forces the heavy architectural constraints of Flatpak and Snap onto the entire ecosystem, including the vast majority of applications that run as standard processes. It is near impossible to debug, shrouded in vagueness, and violates the core Unix philosophy of "do one thing and do it well."

We need a reset. We need a system that respects the simplicity of Unix streams over the complexity of message buses.

**I call it Switchboard.**

This document serves as the technical reference for implementing Switchboard. It relies on standard Unix primitives: Sockets, PIDs, File Descriptors, and the `splice()` syscall.

---

## 1. Architecture Overview

Switchboard adheres to a strict "Dumb Daemon, Smart Handler" philosophy.

1.  **The Switchboard (Daemon):** A stateless connection broker. It maps connections to PIDs and routes them to executables. It contains **zero** policy logic.
2.  **The Handlers (Logic):** System scripts defined by `.desktop` files. They handle UI, persistence, and resource lifecycle.
3.  **The Protocol:** JSON-RPC over Unix Domain Sockets (`AF_UNIX`).

### File System Layout

*   **Socket:** `$XDG_RUNTIME_DIR/switchboard.sock`
*   **System Handlers:** `/usr/share/switchboard/handlers/*.desktop`
*   **User Permissions:** `~/.config/switchboard/permissions/<APP_HASH>.json`

---

## 2. The Daemon Specification

The Daemon is a lightweight background process (likely written in C or Rust). It does not read config files, it does not draw UI, and it does not verify hardware.

### Connection Lifecycle
1.  **Listen:** Bind to `$XDG_RUNTIME_DIR/switchboard.sock`.
2.  **Accept:** Receive client connection (yielding a Client FD).
3.  **Identify:** Use `getsockopt(..., SO_PEERCRED, ...)` to retrieve the secure PID of the caller. This is kernel-enforced; a client cannot spoof its PID.
4.  **Route:** Read the JSON request `{"request": "camera"}` and match it to a `.desktop` file (e.g., `handlers/camera.desktop`).
5.  **Spawn:** Execute the handler defined in the `.desktop` file.
    *   *Crucial Step:* The Daemon `dup2`s the Client FD to a known File Descriptor (e.g., FD 3) in the child process. The Handler inherits the direct connection to the Client.
6.  **Bridge:** Write the Request Payload + PID info into the Handler's **STDIN**.

---

## 3. The Handler Specification (Bash)

The Handler is where the intelligence lives. It is a Bash script that identifies the app, checks the user's saved preferences, and decides *how* to deliver the resource.

### The Identification Strategy
To uniquely identify an app without complex cookies or D-Bus services, we use the **Executable Path**.
1.  Read the PID from STDIN (passed by Daemon).
2.  Resolve `/proc/$PID/exe` to get the binary path.
3.  Hash that path (MD5) to generate a unique `APP_ID`.

### The Logic (`/usr/libexec/switchboard-camera.sh`)

This script handles the policy. Note that it does not perform the socket operations itself; it delegates that to a secure C++ helper via a pipe, ensuring no sensitive data leaks via command line arguments.

```bash
#!/bin/bash

# 1. READ PAYLOAD (Injected via STDIN by Daemon)
# The Daemon passed the Client Connection as FD 3.
read -r JSON_PAYLOAD
REQ_PID=$(echo "$JSON_PAYLOAD" | jq -r '.pid')

# 2. GENERATE APP ID (MD5 of Executable Path)
# This is secure. The kernel controls /proc.
EXE_PATH=$(readlink -f /proc/"$REQ_PID"/exe)
APP_HASH=$(echo -n "$EXE_PATH" | md5sum | awk '{print $1}')
PERM_FILE="$HOME/.config/switchboard/permissions/${APP_HASH}.json"

# 3. CHECK PERSISTENCE
DECISION="ask"
if [ -f "$PERM_FILE" ]; then
    STATUS=$(jq -r '.status' "$PERM_FILE")
    if [ "$STATUS" == "allow" ]; then
        DECISION="allow"
    elif [ "$STATUS" == "deny" ]; then
        DECISION="deny"
    fi
fi

# 4. UI PROMPT (Blocking, if needed)
if [ "$DECISION" == "ask" ]; then
    APP_NAME=$(basename "$EXE_PATH")
    # Using zenity/kdialog/dunst depending on environment
    zenity --question --text="Allow <b>$APP_NAME</b> to access the Camera?"
    if [ $? -eq 0 ]; then
        DECISION="allow"
        # Logic to save to $PERM_FILE would go here
    else
        DECISION="deny"
    fi
fi

# 5. REJECTION
if [ "$DECISION" == "deny" ]; then
    # We send a JSON deny message to FD 3 (Client Socket)
    echo '{"status": "denied"}' >&3
    exit 1
fi

DEVICE="/dev/video0"

# 6. DETERMINE DELIVERY MODE
# Check cgroups or namespaces to detect sandboxing
MODE="direct"
if grep -q "flatpak" "/proc/$REQ_PID/cgroup"; then
    MODE="proxy"
fi

# 7. HAND-OFF TO C++ HELPER
# We construct a JSON configuration for the helper.
# We explicitly tell it to use FD 3 as the client socket.
HELPER_PAYLOAD=$(jq -n \
                  --arg mode "$MODE" \
                  --arg device "$DEVICE" \
                  --argjson socket_fd 3 \
                  '{mode: $mode, device: $device, socket_fd: $socket_fd}')

# Execute helper, piping configuration to STDIN.
# Security: No file paths or modes are visible in 'ps aux'
echo "$HELPER_PAYLOAD" | /usr/libexec/sb-helper

# The Bash script exits. 
# If in Proxy mode, sb-helper keeps running.
# If in Direct mode, sb-helper exits immediately after sending FD.
```

---

## 4. The Helper Specification (C++)

Bash cannot pass file descriptors (`SCM_RIGHTS`) or use `splice()` efficiently. We need a tiny, single-purpose C++ binary to do the heavy lifting.

### `sb-helper.cpp`

This helper reads its configuration from `std::cin` (STDIN) and performs one of two delivery methods.

#### Mode A: Direct Access (`SCM_RIGHTS`)
Used for trusted host apps (e.g., native Firefox, OBS).
1.  Open `/dev/video0`.
2.  Send the raw File Descriptor to the client socket via `SCM_RIGHTS`.
3.  Exit.
**Result:** The application now has direct hardware access (ioctls, auto-focus work natively).

#### Mode B: The Splice Proxy
Used for sandboxed apps (e.g., Flatpaks). This prevents the app from issuing hardware-level `ioctl` commands but allows full data flow.
1.  Open `/dev/video0`.
2.  Create a standard Unix Pipe.
3.  Send the **Read-End** of the pipe to the client via `SCM_RIGHTS`.
4.  Enter a `splice()` loop.

```cpp
// Conceptual C++ Implementation for sb-helper

#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
// ... json parsing lib ...

int main() {
    // 1. READ CONFIG FROM STDIN (Secure)
    std::string input_json;
    std::getline(std::cin, input_json);
    auto config = parse_json(input_json); 
    
    std::string mode = config["mode"];      
    std::string device = config["device"];  
    int client_sock = config["socket_fd"];  // FD 3

    int device_fd = open(device.c_str(), O_RDWR);
    if (device_fd < 0) return 1;

    if (mode == "direct") {
        // --- MODE A: DIRECT PASSING ---
        // Send the raw FD so the app can use ioctls
        send_fd(client_sock, device_fd);
        return 0; 
    } 
    else if (mode == "proxy") {
        // --- MODE B: SPLICE PROXY ---
        int pipefd[2];
        pipe(pipefd);

        // Send the pipe's read-end to the client
        send_fd(client_sock, pipefd[0]);
        close(pipefd[0]); // We don't need the read end

        // Zero-Copy Data Pump
        while (true) {
            // Move data from Device -> Pipe Write-End
            // Entirely kernel-space. No buffer copying.
            ssize_t sent = splice(device_fd, NULL, pipefd[1], NULL, 
                                  4096, SPLICE_F_MOVE | SPLICE_F_MORE);
            if (sent <= 0) break;
        }
        return 0;
    }
    return 1;
}
```

---

## 5. Security & Isolation

### Identity Verification
XDG Portals rely on request tokens. Switchboard relies on **PIDs**, which are verified by the kernel via `SO_PEERCRED`. You cannot lie about your PID over a Unix socket.

### Privacy by Default
1.  **Daemon -> Handler:** PID and Request Metadata passed via **STDIN**.
2.  **Handler -> Helper:** Device paths and Mode passed via **STDIN**.
**Result:** Running `ps aux` reveals nothing but `/usr/libexec/switchboard-camera.sh` and `/usr/libexec/sb-helper`. No file paths, no user info.

### Revocability (The Proxy Advantage)
In **Proxy Mode**, the C++ helper remains running as the "Custodian" of the stream.
If the user wants to revoke permission mid-session:
1.  The system sends `SIGTERM` to the specific `sb-helper` process.
2.  The kernel automatically closes the write-end of the pipe.
3.  The Sandboxed App immediately receives `EOF` on its file descriptor.
The stream is cut instantly.

---

## Summary

Switchboard is not just a replacement; it is a simplification. It removes the "Black Box" of the XDG Portal service and replaces it with transparent, debuggable, standard Unix processes.

*   **Communication:** JSON over Unix Sockets.
*   **Identity:** Kernel-verified PIDs & Filesystem Paths.
*   **Delivery:** `SCM_RIGHTS` (Direct) and `splice()` (Proxy).
*   **Policy:** Simple Bash scripts and JSON files.

We don't need D-Bus to open a camera. We just need the keys to the file.
