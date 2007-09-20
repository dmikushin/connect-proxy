#!/usr/bin/make -f
PACKAGE?=connect-proxy
#URL=http://www.meadowy.org/~gotoh/projects/connect/browser/trunk/connect.c?format=raw
URL=http://www.meadowy.org/~gotoh/ssh/connect.c
INSTALL_DIR?=${DESTDIR}/usr
OBJS?=connect.o

all default: ${PACKAGE} 

install: ${PACKAGE}
	-mkdir -p ${INSTALL_DIR}/bin/
	install ${PACKAGE} ${INSTALL_DIR}/bin/
#	ln -fs ${PACKAGE} ${INSTALL_DIR}/bin/connect

${PACKAGE}: ${OBJS}
	    ${CC} -o $@ $^ ${LDFLAGS} 
clean: 
	${RM} ${PACKAGE} ${PACKAGE}.o *~ ${OBJS} || echo "# $@: $^"

# connect.c:
#	wget -O $@ "${URL}"

update:
	wget -O connect.c "${URL}"

LICENCE: /usr/share/apps/LICENSES/GPL_V2
	ln -fs $^ $@

#eof "$Id: connect-proxy/Makefile --  rzr@users.sf.net $"
