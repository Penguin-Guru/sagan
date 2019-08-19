## Problems:
##	Default should probably install to "/usr/local", but this does not. I'm not sure why.
##	On my system, "$(SpoolPath)" expands to "/var/lib". Again, I don't know why.

AUTOMAKE_OPIONS=foreign no-dependencies subdir-objects
ACLOCAL_AMFLAGS = -I m4
SUBDIRS = src

INSTALL_PROGRAM ::= $(INSTALL) -m 755
#man8dir ::= "$(mandir)/man8"
#ifeq ($(origin man8dir),undefined)
#ifndef "$(man8dir)"
#man8dir ::= "$(mandir)/man8"
#endif
man8dir ?= "$(mandir)/man8"

RunPath ::= "$(DESTDIR)$(runstatedir)/sagan"
SpoolPath ::= "$(DESTDIR)$(localstatedir)/spool/sagan"
LogPath ::= "$(DESTDIR)$(localstatedir)/log/sagan"
ConfPath ::= "$(DESTDIR)$(sysconfdir)/sagan"
RulePath ::= "$(ConfPath)/rules"

#INCLUDES = @INCLUDES@

# Install BFD include file, and others that it needs.
#install-data-local: 
#	@$(NORMAL_INSTALL)
#	$(mkinstalldirs) $(sysconfdir)
#	$(INSTALL_DATA)sagan.conf $(sysconfdir)/sagan.yaml


.NOTPARALLEL: install-done
install-data-local: install-man install-process install-config install-program install-done


install-man:
	test -d "$(DESTDIR)$(man8dir)" || /bin/mkdir -p "$(DESTDIR)$(man8dir)"
	$(INSTALL_DATA) etc/sagan.8 "$(DESTDIR)$(man8dir)"



install-process: install-process-logs install-process-spool install-process-run

install-process-logs:
	test -d "$(LogPath)" || /bin/mkdir -p "$(LogPath)"
	$(INSTALL) -d "$(LogPath)"

install-process-spool:
	test -d "$(SpoolPath)" || /bin/mkdir -p "$(SpoolPath)"
	test -p "$(SpoolPath)/input.fifo" || mkfifo -m o-rwx "$(SpoolPath)/input.fifo"
	/bin/chown -R 'sagan:adm' "$(SpoolPath)"

install-process-run:
	$(INSTALL) -d -o sagan "$(DESTDIR)/var/run/sagan"

#	test -e "$(RunPath)/sagan.pid" && echo "PID file already exists: $(RunPath)/sagan.pid"


install-config:
	test -d "$(ConfPath)" || /bin/mkdir -p "$(ConfPath)"
	test -f "$(ConfPath)/sagan.yaml" || $(INSTALL_DATA) etc/sagan.yaml "$(ConfPath)/sagan.yaml"
	test -d "$(ConfPath)/rules" || /bin/mkdir -p "$(ConfPath)/rules"


install-program:
	test -d "$(DESTDIR)$(sbindir)" || /bin/mkdir -p "$(DESTDIR)$(sbindir)"
	$(INSTALL_PROGRAM) src/sagan "$(DESTDIR)$(sbindir)/sagan"


install-done:
	@echo ""
	@echo "------------------------------------------------------------------------------"
	@echo "Sagan has been installed! You still need to do a few more things before your"
	@echo "up and running.  For more information, see https://sagan.readthedocs.io"
	@echo "------------------------------------------------------------------------------"
	@echo ""
