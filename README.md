[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.15623400.svg)](https://doi.org/10.5281/zenodo.15623400) [![DOI](https://img.shields.io/github/license/NESA-Lab/FirmRCA.svg)](https://github.com/NESA-Lab/FirmRCA?tab=GPL-3.0-1-ov-file) [![Static Badge](https://img.shields.io/badge/IEEE%20S%26P-10.1109%2FSP61157.2025.00002-green)](https://www.computer.org/csdl/proceedings-article/sp/2025/223600a002/21B7PVDny6I)

# FirmRCA

Embedded Firmware Root Cause Analysis.

This repo contains the source code of the paper "FirmRCA: Towards Post-Fuzzing Analysis on ARM Embedded Firmware with Efficient Event-based Fault Localization"

## NOTE

*During the development of FirmRCA, footprint collection and root cause analysis were carried out sequentially on two separate servers. However, the server responsible for footprint collection suffered a hard drive failure. As a result, the version of fuzzware used by the current repository’s fuzzware-emulator is uncertain, which may introduce potential instability in the experimental results.*

## How to Install

Step 1. Clone the repo.

```shell
git clone https://github.com/NESA-Lab/FirmRCA
cd ./FirmRCA
```

Step 2. Install the dependencies.

Install the capstone.

```shell
git clone https://github.com/capstone-engine/capstone.git
cd ./capstone
git reset --hard 622059530f172b1570a424e3f7ef5fda8c00dab0 # not sure if new features in the latest commit affect our code
```

Then you should compile and install capstone as system library, following the instructions in capstone.
For example, on *nix:

```shell
sudo ./make.sh
sudo ./make.sh install
```

Some python packages:

```shell
pip3 install matplotlib pandas pyyaml openpyxl 
```

Step 3. Compile the capnproto library.

(Option) Configure c-capnproto, if you want to modify tracing data.

```shell
curl -O https://capnproto.org/capnproto-c++-1.0.1.tar.gz
tar zxf capnproto-c++-1.0.1.tar.gz
cd ./capnproto-c++-1.0.1
./configure
make -j4 check
sudo make install
```

```shell
git clone https://gitlab.com/dkml/ext/c-capnproto.git
cd ./c-capnproto
sudo apt install ninja-build
cmake --preset=ci-linux_x86_64
cmake --build --preset=ci-tests
```

Compile the library.

```shell
cd ./test_c_capnproto
# before capnp compile, you can modify bintrace.capnp if need
capnp compile -o ./c-capnproto/build/capnpc-c bintrace.capnp 
gcc *.c -I./ -shared -fPIC -o libcapnproto.so
cp ./libcapnproto.so ../src/lib
```

Step 4. Compile the project binary

Note that you should comment/uncomment the settings in `Makefile.am`.

```shell
cd ./src
./autogen.sh
./configure
cd src
make
```

If something wrong occurs when running `./configure`, please make sure these compilation files use LF instead of CRLF. You can also check [POMP](https://github.com/junxzm1990/pomp) for installation reference.

## Dataset 

We prepare 3 testsuites as a demo in the `testsuites-demo.zip` file. You can download full dataset from [10.5281/zenodo.15623399](https://doi.org/10.5281/zenodo.15623399). 

If you want to generate more testcases, you can prepare your files like this:

```
.
├── testsuites
│   ├── <something-your-bin-name1>
│   │   ├── firmware.bin
│   ├── <something-your-bin-name2>
│   │   ├── firmware.bin
│   ├── <something-your-bin-name3>
│   │   ├── firmware.bin

```

`<something-your-bin-name1>` should be the value of the `name` key in `config.yml`. You should also specify `bin_load_addr` that loads the binary.

Then please refer to [fuzzware-fuzzer](https://github.com/fuzzware-fuzzer/fuzzware-emulator) to setup the environment. Please do not clone the their repository in that the unicorn version may be different. Use the fuzzware-emulator in this repository, instead.

Then, run `python dataset.py` to generate your own dataset.

## TODO

Port over ARM CortexM specific implementations to ARM 32bit
- Set capstone to CS_MODE_ARM instead of CS_MODE_THUMB (DONE)
- ARM 32bit contains instructions with conditional code (eg. MOVNE), check if need to handle differently
    - ```c 
        /// Instruction structure
        typedef struct cs_arm {
            bool usermode;	///< User-mode registers to be loaded (for LDM/STM instructions)
            int vector_size; 	///< Scalar size for vector instructions
            arm_vectordata_type vector_data; ///< Data type for elements of vector instructions
            arm_cpsmode_type cps_mode;	///< CPS mode for CPS instruction
            arm_cpsflag_type cps_flag;	///< CPS mode for CPS instruction
            ARMCC_CondCodes cc;		///< conditional code for this insn
            ARMVCC_VPTCodes vcc;	///< Vector conditional code for this instruction.
            bool update_flags;	///< does this insn update flags?
            bool post_index;	///< only set if writeback is 'True', if 'False' pre-index, otherwise post.
            int /* arm_mem_bo_opt */ mem_barrier;	///< Option for some memory barrier instructions
            // Check ARM_PredBlockMask for encoding details.
            uint8_t /* ARM_PredBlockMask */ pred_mask;	///< Used by IT/VPT block instructions.
            /// Number of operands of this instruction,
            /// or 0 when instruction has no operand.
            uint8_t op_count;

            cs_arm_op operands[MAX_ARM_OPS];	///< operands for this instruction.
        } cs_arm;
    - `cs_arm` struct in capstone has a field to handle cc, not sure if needed to check
- ARM 32bit instruction contains shift types after ADD, AND, MOV, etc
    - Need to account for shift values. Can be accessed through op[i].shift.type (eg. ARM_SFT_LSL) and op[i].value (eg. 2)
    - Modify instruction resolvers affected by shift type to resolve shift values
    - Find a way to store shift type and shift value
    - change `get_regval_from_coredump` and `get_memval_from_coredump` in `re_opdvalue.c` 
- ARM 32bit instructions may contain post-increment for ldr/str instructions, which ARM-Cortex M does not have
    - Modify handler/resolver for post increments
- STM instruction does not seem to correctly increment addresses which define nodes write to