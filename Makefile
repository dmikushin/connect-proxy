#gmake
PACKAGE ?= connect-proxy
URL ?= http://www.taiyo.co.jp/~gotoh/ssh/connect.c
INSTALL_DIR ?= ${DESTDIR}/usr

OBJS ?= connect.o

default: ${PACKAGE} 

install: ${PACKAGE}
	 -mkdir -p ${INSTALL_DIR}/bin/
	 install -s ${PACKAGE} ${INSTALL_DIR}/bin/


${PACKAGE}: ${OBJS}
	    ${CC} -o $@ $^
clean: 
	${RM} ${PACKAGE} ${PACKAGE}.o *~ ${OBJS}

# connect.c:
#	wget ${URL}

LICENCE: /usr/share/apps/LICENSES/GPL_V2
	ln -fs $^ $@

# EOF
