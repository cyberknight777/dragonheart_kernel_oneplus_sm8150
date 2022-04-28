#!/usr/bin/bash
# Written by: cyberknight777
# YAKB v1.0
# Copyright (c) 2022-2023 Cyber Knight <cyberknight755@gmail.com>
#
#			GNU GENERAL PUBLIC LICENSE
#			 Version 3, 29 June 2007
#
# Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
# Everyone is permitted to copy and distribute verbatim copies
# of this license document, but changing it is not allowed.

# Some Placeholders: [!] [*] [✓] [✗]

# Default defconfig to use for builds.
export CONFIG=dragonheart_defconfig

# Default directory where kernel is located in.
KDIR=$(pwd)
export KDIR

# Default linker to use for builds.
export LINKER="ld.lld"

# Device name.
export DEVICE="OnePlus 7 Series"

# Device codename.
export CODENAME="op7"

# Builder name.
export BUILDER="cyberknight777"

# Kernel repository URL.
export REPO_URL="https://github.com/cyberknight777/dragonheart_kernel_oneplus_sm8150"

# Commit hash of HEAD.
COMMIT_HASH=$(git rev-parse --short HEAD)
export COMMIT_HASH

# Telegram Information. Set 1 to enable. | Set 0 to disable.
export TGI=1
export CHATID=-1001361882613

# Necessary variables to be exported.
export ci
export version

# Number of jobs to run.
PROCS=$(nproc --all)
export PROCS

# Compiler to use for builds.
export COMPILER=gcc

# Requirements
if [ "${ci}" != 1 ]; then
    if ! hash dialog make curl wget unzip find 2>/dev/null; then
        echo -e "\n\e[1;31m[✗] Install dialog, make, curl, wget, unzip, and find! \e[0m"
        exit 1
    fi
fi

if [[ "${COMPILER}" = gcc ]]; then
    if [ ! -d "${KDIR}/gcc64" ]; then
        wget -O "${KDIR}"/64.zip https://github.com/mvaisakh/gcc-arm64/archive/1a4410a4cf49c78ab83197fdad1d2621760bdc73.zip
        unzip "${KDIR}"/64.zip
        mv "${KDIR}"/gcc-arm64-1a4410a4cf49c78ab83197fdad1d2621760bdc73 "${KDIR}"/gcc64
    fi

    if [ ! -d "${KDIR}/gcc32" ]; then
        wget -O "${KDIR}"/32.zip https://github.com/mvaisakh/gcc-arm/archive/c8b46a6ab60d998b5efa1d5fb6aa34af35a95bad.zip
        unzip "${KDIR}"/32.zip
        mv "${KDIR}"/gcc-arm-c8b46a6ab60d998b5efa1d5fb6aa34af35a95bad "${KDIR}"/gcc32
    fi

    if [ ! -f "${KDIR}/ld.lld" ]; then
        wget https://gitlab.com/zlatanr/dora-clang-1/-/raw/master/bin/lld -O ld.lld && chmod +x ld.lld
    fi

    KBUILD_COMPILER_STRING=$("${KDIR}"/gcc64/bin/aarch64-elf-gcc --version | head -n 1)
    export KBUILD_COMPILER_STRING
    export PATH="${KDIR}"/gcc32/bin:"${KDIR}"/gcc64/bin:/usr/bin/:${PATH}
    MAKE+=(
        ARCH=arm64
        O=out
        CROSS_COMPILE=aarch64-elf-
        CROSS_COMPILE_ARM32=arm-eabi-
        LD="${KDIR}"/ld.lld
        AR=llvm-ar
        OBJDUMP=llvm-objdump
        STRIP=llvm-strip
        CC=aarch64-elf-gcc
    )

elif [[ "${COMPILER}" = clang ]]; then
    if [ ! -d "${KDIR}/proton-clang" ]; then
        wget https://github.com/kdrag0n/proton-clang/archive/refs/heads/master.zip
        unzip "${KDIR}"/master.zip
        mv "${KDIR}"/proton-clang-master "${KDIR}"/proton-clang
    fi

    KBUILD_COMPILER_STRING=$("${KDIR}"/proton-clang/bin/clang -v 2>&1 | head -n 1 | sed 's/(https..*//' | sed 's/ version//')
    export KBUILD_COMPILER_STRING
    export PATH=$KDIR/proton-clang/bin/:/usr/bin/:${PATH}
    MAKE+=(
        ARCH=arm64
        O=out
        CROSS_COMPILE=aarch64-linux-gnu-
        CROSS_COMPILE_ARM32=arm-linux-gnueabi-
        LD="${LINKER}"
        AR=llvm-ar
        AS=llvm-as
        NM=llvm-nm
        OBJDUMP=llvm-objdump
        STRIP=llvm-strip
        CC=clang
    )
fi

if [ ! -d "${KDIR}/anykernel3-dragonheart/" ]; then
    git clone --depth=1 https://github.com/cyberknight777/anykernel3 -b op7 anykernel3-dragonheart
fi

if [ "${ci}" != 1 ]; then
    if [ -z "${kver}" ]; then
        echo -ne "\e[1mEnter kver: \e[0m"
        read -r kver
    else
        export KBUILD_BUILD_VERSION=${kver}
    fi

    if [ -z "${zipn}" ]; then
        echo -ne "\e[1mEnter zipname: \e[0m"
        read -r zipn
    fi

else
    export KBUILD_BUILD_VERSION=$DRONE_BUILD_NUMBER
    export KBUILD_BUILD_HOST=$DRONE_SYSTEM_HOST
    export KBUILD_BUILD_USER=$BUILDER
    export VERSION=$version
    kver=$KBUILD_BUILD_VERSION
    zipn=DragonHeart-op7-${VERSION}
fi

# A function to exit on SIGINT.
exit_on_signal_SIGINT() {
    echo -e "\n\n\e[1;31m[✗] Received INTR call - Exiting...\e[0m"
    exit 0
}
trap exit_on_signal_SIGINT SIGINT

# A function to send message(s) via Telegram's BOT api.
tg() {
    curl -sX POST https://api.telegram.org/bot"${TOKEN}"/sendMessage \
        -d chat_id="${CHATID}" \
        -d parse_mode=Markdown \
        -d disable_web_page_preview=true \
        -d text="$1" &>/dev/null
}

# A function to send file(s) via Telegram's BOT api.
tgs() {
    MD5=$(md5sum "$1" | cut -d' ' -f1)
    curl -fsSL -X POST -F document=@"$1" https://api.telegram.org/bot"${TOKEN}"/sendDocument \
        -F "chat_id=${CHATID}" \
        -F "parse_mode=Markdown" \
        -F "caption=$2 | *MD5*: \`$MD5\`"
}

# A function to clean kernel source prior building.
clean() {
    echo -e "\n\e[1;93m[*] Cleaning source and out/ directory! \e[0m"
    make clean && make mrproper && rm -rf "${KDIR}"/out
    echo -e "\n\e[1;32m[✓] Source cleaned and out/ removed! \e[0m"
}

# A function to regenerate defconfig.
rgn() {
    echo -e "\n\e[1;93m[*] Regenerating defconfig! \e[0m"
    make "${MAKE[@]}" $CONFIG
    cp -rf "${KDIR}"/out/.config "${KDIR}"/arch/arm64/configs/$CONFIG
    echo -e "\n\e[1;32m[✓] Defconfig regenerated! \e[0m"
}

# A function to open a menu based program to update current config.
mcfg() {
    rgn
    echo -e "\n\e[1;93m[*] Making Menuconfig! \e[0m"
    make "${MAKE[@]}" menuconfig
    cp -rf "${KDIR}"/out/.config "${KDIR}"/arch/arm64/configs/$CONFIG
    echo -e "\n\e[1;32m[✓] Saved Modifications! \e[0m"
}

# A function to build the kernel.
img() {
    if [[ "${TGI}" != "0" ]]; then
        tg "
*Build Number*: \`${kver}\`
*Builder*: \`${BUILDER}\`
*Device*: \`${DEVICE} [${CODENAME}]\`
*Kernel Version*: \`$(make kernelversion 2>/dev/null)\`
*Date*: \`$(date)\`
*Zip Name*: \`${zipn}\`
*Compiler*: \`${KBUILD_COMPILER_STRING}\`
*Linker*: \`$("${KDIR}"/ld.lld -v | head -n1 | sed 's/(compatible with [^)]*)//' |
            head -n 1 | perl -pe 's/\(http.*?\)//gs' | sed -e 's/  */ /g' -e 's/[[:space:]]*$//')\`
*Branch*: \`$(git rev-parse --abbrev-ref HEAD)\`
*Last Commit*: [${COMMIT_HASH}](${REPO_URL}/commit/${COMMIT_HASH})
"
    fi
    rgn
    echo -e "\n\e[1;93m[*] Building Kernel! \e[0m"
    BUILD_START=$(date +"%s")
    time make -j"$PROCS" "${MAKE[@]}" Image dtbo.img dtb.img 2>&1 | tee log.txt
    BUILD_END=$(date +"%s")
    DIFF=$((BUILD_END - BUILD_START))
    if [ -f "${KDIR}/out/arch/arm64/boot/Image" ]; then
        if [[ "${SILENT}" != "1" ]]; then
            tg "*Kernel Built after $((DIFF / 60)) minute(s) and $((DIFF % 60)) second(s)*"
        fi
        echo -e "\n\e[1;32m[✓] Kernel built after $((DIFF / 60)) minute(s) and $((DIFF % 60)) second(s)! \e[0m"
    else
        if [[ "${TGI}" != "0" ]]; then
            tgs "log.txt" "*Build failed*"
        fi
        echo -e "\n\e[1;31m[✗] Build Failed! \e[0m"
        exit 1
    fi
}

# A function to build DTBs.
dtb() {
    rgn
    echo -e "\n\e[1;93m[*] Building DTBS! \e[0m"
    time make -j"$PROCS" "${MAKE[@]}" dtbs dtbo.img dtb.img
    echo -e "\n\e[1;32m[✓] Built DTBS! \e[0m"
}

# A function to build out-of-tree modules.
mod() {
    if [[ "${TGI}" != "0" ]]; then
        tg "*Building Modules!*"
    fi
    rgn
    echo -e "\n\e[1;93m[*] Building Modules! \e[0m"
    mkdir -p "${KDIR}"/out/modules
    make "${MAKE[@]}" modules_prepare
    make -j"$PROCS" "${MAKE[@]}" modules INSTALL_MOD_PATH="${KDIR}"/out/modules
    make "${MAKE[@]}" modules_install INSTALL_MOD_PATH="${KDIR}"/out/modules
    find "${KDIR}"/out/modules -type f -iname '*.ko' -exec cp {} "${KDIR}"/anykernel3-dragonheart/modules/system/lib/modules/ \;
    echo -e "\n\e[1;32m[✓] Built Modules! \e[0m"
}

# A function to build an AnyKernel3 zip.
mkzip() {
    if [[ "${TGI}" != "0" ]]; then
        tg "*Building zip!*"
    fi
    echo -e "\n\e[1;93m[*] Building zip! \e[0m"
    mv "${KDIR}"/out/arch/arm64/boot/dtbo.img "${KDIR}"/anykernel3-dragonheart
    mv "${KDIR}"/out/arch/arm64/boot/dtb.img "${KDIR}"/anykernel3-dragonheart
    mv "${KDIR}"/out/arch/arm64/boot/Image "${KDIR}"/anykernel3-dragonheart
    cd "${KDIR}"/anykernel3-dragonheart || exit 1
    zip -r9 "$zipn".zip . -x ".git*" -x "README.md" -x "LICENSE" -x "*.zip"
    echo -e "\n\e[1;32m[✓] Built zip! \e[0m"
    if [[ "${TGI}" != "0" ]]; then
        tgs "${zipn}.zip" "*#${kver} ${KBUILD_COMPILER_STRING}*"
    fi
}

# A function to build specific objects.
obj() {
    rgn
    echo -e "\n\e[1;93m[*] Building ${1}! \e[0m"
    time make -j"$PROCS" "${MAKE[@]}" "$1"
    echo -e "\n\e[1;32m[✓] Built ${1}! \e[0m"
}

# A function to uprev localversion in defconfig.
upr() {
    echo -e "\n\e[1;93m[*] Bumping localversion to -DragonHeart-${1}! \e[0m"
    "${KDIR}"/scripts/config --file "${KDIR}"/arch/arm64/configs/$CONFIG --set-str CONFIG_LOCALVERSION "-DragonHeart-${1}"
    rgn
    if [ "${ci}" != 1 ]; then
        git add arch/arm64/configs/$CONFIG
        git commit -S -s -m "dragonheart_defconfig: Bump to \`${1}\`"
    fi
    echo -e "\n\e[1;32m[✓] Bumped localversion to -DragonHeart-${1}! \e[0m"
}

# A function to showcase the options provided for args-based usage.
helpmenu() {
    echo -e "\n\e[1m
usage: kver=<version number> zipn=<zip name> $0 <arg>

example: $0 --kver=69 --zipn=Kernel-Beta mcfg
example: $0 --kver=420 --zipn=Kernel-Beta mcfg img
example: $0 --kver=69420 --zipn=Kernel-Beta mcfg img mkzip
example: $0 --kver=1 --zipn=Kernel-Beta --obj=drivers/android/binder.o
example: $0 --kver=2 --zipn=Kernel-Beta --obj=kernel/sched/
example: $0 --kver=3 --zipn=Kernel-Beta--upr=r16

	 mcfg   Runs make menuconfig
	 img    Builds Kernel
	 dtb    Builds dtb(o).img
	 mod    Builds out-of-tree modules
	 mkzip  Builds anykernel3 zip
	 --obj  Builds specific driver/subsystem
	 rgn    Regenerates defconfig
	 --upr  Uprevs kernel version in defconfig\e[0m
	 --kver kernel buildversion
	 --zipn zip name"
}

# A function to setup menu-based usage.
ndialog() {
    HEIGHT=16
    WIDTH=40
    CHOICE_HEIGHT=30
    BACKTITLE="Yet Another Kernel Builder"
    TITLE="YAKB v1.0"
    MENU="Choose one of the following options: "
    OPTIONS=(1 "Build kernel"
        2 "Build DTBs"
        3 "Build modules"
        4 "Open menuconfig"
        5 "Regenerate defconfig"
        6 "Uprev localversion"
        7 "Build AnyKernel3 zip"
        8 "Build a specific object"
        9 "Exit"
    )
    CHOICE=$(dialog --clear \
        --backtitle "$BACKTITLE" \
        --title "$TITLE" \
        --menu "$MENU" \
        $HEIGHT $WIDTH $CHOICE_HEIGHT \
        "${OPTIONS[@]}" \
        2>&1 >/dev/tty)
    clear
    case "$CHOICE" in
    1)
        clear
        img
        echo -ne "\e[1mPress enter to continue or 0 to exit! \e[0m"
        read -r a1
        if [ "$a1" == "0" ]; then
            exit 0
        else
            clear
            ndialog
        fi
        ;;
    2)
        clear
        dtb
        echo -ne "\e[1mPress enter to continue or 0 to exit! \e[0m"
        read -r a1
        if [ "$a1" == "0" ]; then
            exit 0
        else
            clear
            ndialog
        fi
        ;;
    3)
        clear
        mod
        echo -ne "\e[1mPress enter to continue or 0 to exit! \e[0m"
        read -r a1
        if [ "$a1" == "0" ]; then
            exit 0
        else
            clear
            ndialog
        fi
        ;;
    4)
        clear
        mcfg
        echo -ne "\e[1mPress enter to continue or 0 to exit! \e[0m"
        read -r a1
        if [ "$a1" == "0" ]; then
            exit 0
        else
            clear
            ndialog
        fi
        ;;
    5)
        clear
        rgn
        echo -ne "\e[1mPress enter to continue or 0 to exit! \e[0m"
        read -r a1
        if [ "$a1" == "0" ]; then
            exit 0
        else
            clear
            ndialog
        fi
        ;;
    6)
        dialog --inputbox --stdout "Enter version number: " 15 50 | tee .t
        ver=$(cat .t)
        clear
        upr "$ver"
        rm .t
        echo -ne "\e[1mPress enter to continue or 0 to exit! \e[0m"
        read -r a1
        if [ "$a1" == "0" ]; then
            exit 0
        else
            clear
            ndialog
        fi
        ;;
    7)
        mkzip
        echo -ne "\e[1mPress enter to continue or 0 to exit! \e[0m"
        read -r a1
        if [ "$a1" == "0" ]; then
            exit 0
        else
            clear
            ndialog
        fi
        ;;
    8)
        dialog --inputbox --stdout "Enter object path: " 15 50 | tee .f
        ob=$(cat .f)
        if [ -z "$ob" ]; then
            dialog --inputbox --stdout "Enter object path: " 15 50 | tee .f
        fi
        clear
        obj "$ob"
        rm .f
        echo -ne "\e[1mPress enter to continue or 0 to exit! \e[0m"
        read -r a1
        if [ "$a1" == "0" ]; then
            exit 0
        else
            clear
            ndialog
        fi
        ;;
    9)
        echo -e "\n\e[1m Exiting YAKB...\e[0m"
        sleep 3
        exit 0
        ;;
    esac
}

if [ "${ci}" == 1 ]; then
    upr "${version}"
fi

if [[ -z $* ]]; then
    ndialog
fi

for arg in "$@"; do
    case "${arg}" in
    "mcfg")
        mcfg
        ;;
    "img")
        img
        ;;
    "dtb")
        dtb
        ;;
    "mod")
        mod
        ;;
    "mkzip")
        mkzip
        ;;
    "--obj="*)
        object="${arg#*=}"
        if [[ -z "$object" ]]; then
            echo "Use --obj=filename.o"
            exit 1
        else
            obj "$object"
        fi
        ;;
    "rgn")
        rgn
        ;;
    "--upr="*)
        vers="${arg#*=}"
        if [[ -z "$vers" ]]; then
            echo "Use --upr=version"
            exit 1
        else
            upr "$vers"
        fi
        ;;
    "help")
        helpmenu
        exit 1
        ;;
    *)
        helpmenu
        exit 1
        ;;
    esac
done
