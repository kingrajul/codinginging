// This file is intentionally served as text/plain (see nginx.conf).
// Without X-Content-Type-Options: nosniff, legacy browsers (IE/old Edge)
// execute it as JavaScript despite the wrong Content-Type.
alert("MIME sniffing: this file was served as text/plain but executed as JavaScript!");
