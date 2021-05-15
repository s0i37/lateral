midl /app_config lateral.idl

cl /c lateral_s.c

cl /c lateral.c

link /out:lateral.exe lateral.c lateral_s.c
