

CC = gcc
PP = g++
CFLAGS = -g -Wall -Werror
OS = $(shell uname -s)
PROC = $(shell uname -p)
EXEC_SUFFIX=$(OS)-$(PROC)

ifeq ("$(OS)", "SunOS")
	OSLIB=-L/opt/csw/lib -R/opt/csw/lib -lsocket -lnsl
	OSINC=-I/opt/csw/include
	OSDEF=-DSOLARIS
else
ifeq ("$(OS)", "Darwin")
	OSLIB=
	OSINC=
	OSDEF=-DDARWIN
else
	OSLIB=
	OSINC=
	OSDEF=-DLINUX
endif
endif

all:  df_client df_server

df_client: df_client.cpp
	$(PP) $(CFLAGS) $(OSINC) $(OSLIB) $(OSDEF) -o df_client df_client.cpp

df_server: df_server.cpp
	$(PP) $(CFLAGS) $(OSINC) $(OSLIB) $(OSDEF) -o df_server df_server.cpp

clean:
	-rm -rf df_client df_server
