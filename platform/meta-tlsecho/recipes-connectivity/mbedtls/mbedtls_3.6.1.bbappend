FILESEXTRAPATHS:prepend := "${THISDIR}/${PN}:"

SRC_URI += " \
    file://0001-ssl-add-local-L1-TLS-1.3-server-signing-feature.patch \
    file://0002-ssl_tls13-add-synchronous-external-server-signing.patch \
    file://0003-ssl-add-TLS-1.3-crypto-backend-lifecycle-framework.patch \
    file://0004-ssl-add-external-transform-ownership-discrimination.patch \
    file://0005-ssl-extend-TLS-1.3-backend-API-for-record-AEAD.patch \
    file://0006-ssl_tls13-route-records-through-external-backend-transforms.patch \
    file://0007-ssl_tls13-add-D2-key-schedule-and-Finished-backend-hooks.patch \
"

# Local build-host workaround:
# Ensure do_package uses Yocto's tar-native rather than the host tar through
# hosttools. This avoids pseudo/host-tar dirfd tracking failures observed during
# perform_packagecopy.
DEPENDS:append = " tar-native"

# Local build-host workaround:
# do_package's perform_packagecopy uses "tar" under pseudo. Ensure the task
# sysroot can use Yocto's tar-native instead of relying only on hosttools tar.
do_package[depends] += "tar-native:do_populate_sysroot"

# Local workaround for mbedtls:do_package on this build host:
# The default package.bbclass perform_packagecopy uses a tar | tar pipeline under
# pseudo. On this host it fails with:
#   got *at() syscall for unknown directory
#   tar: ./usr/include: Cannot mkdir: Bad address
# This recipe-local override copies ${D} to ${PKGD} via Python instead of tar.
python perform_packagecopy () {
    import os
    import shutil
    import bb

    src_root = d.getVar("D")
    dst_root = d.getVar("PKGD")

    bb.note("mbedtls: using Python package copy workaround instead of tar pipeline")

    if os.path.exists(dst_root):
        shutil.rmtree(dst_root)

    os.makedirs(dst_root, exist_ok=True)

    def copy_entry(src, dst):
        if os.path.islink(src):
            os.symlink(os.readlink(src), dst)
            try:
                shutil.copystat(src, dst, follow_symlinks=False)
            except NotImplementedError:
                pass
        elif os.path.isdir(src):
            os.makedirs(dst, exist_ok=True)
            shutil.copystat(src, dst, follow_symlinks=False)
            for name in os.listdir(src):
                copy_entry(os.path.join(src, name), os.path.join(dst, name))
        else:
            shutil.copy2(src, dst, follow_symlinks=False)

    for name in os.listdir(src_root):
        copy_entry(os.path.join(src_root, name), os.path.join(dst_root, name))

    if bb.utils.contains("DISTRO_FEATURES", "chrpath", True, False, d):
        rpath_replace(dst_root, d)
}

# Local build-host workaround:
# dpkg-deb invokes "tar" internally during do_package_write_deb. Ensure this
# task also has Yocto's tar-native in its task sysroot.
do_package_write_deb[depends] += "tar-native:do_populate_sysroot"

# Local build-host workaround:
# dpkg-deb internally invokes tar during do_package_write_deb. Under pseudo on
# this host, that tar subprocess fails with "Cannot stat: Bad address".
# Disable pseudo only for dpkg-deb and let dpkg-deb force root:root ownership
# in the generated archive.
DPKG_BUILDCMD = "PSEUDO_DISABLED=1 dpkg-deb --root-owner-group"

# Scenario D2 fix: external transforms must still advertise AEAD mode to the
# normal TLS record layer.
SRC_URI += "file://0008-ssl_tls13-initialize-external-D2-transform-mode-metadata.patch"

# Scenario D3: server-side ECDHE key generation and shared secret are backend-owned.
SRC_URI += "file://0009-ssl_tls13-add-D3-external-server-ECDHE-backend-hooks.patch"

# Scenario D4: TLS 1.3 resumption/NewSessionTicket/PSK-ECDHE backend hooks.
SRC_URI += "file://0010-ssl_tls13-add-D4-resumption-backend-hooks.patch"
