#!/usr/bin/env python3
"""Build the pinned Core daemon with the opt-in nonstandard policy patch."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import urllib.request

HERE=Path(__file__).resolve().parent
ROOT=Path('/private/tmp/bitcoin-core-nonstandard-build')
TOOLS=Path('/private/tmp/bitcoin-core-nonstandard-tools/bin')
COMMIT='49faec4f87f5cd19c88db01a82e5c68b087c8227'
PACKAGES=[
 ('core',f'https://codeload.github.com/bitcoin/bitcoin/tar.gz/{COMMIT}',
  'f0dd7dcb92fe08e39c3cd74981d579b5113c54c90a124956d6e264c3a419e051'),
 ('boost','https://github.com/boostorg/boost/releases/download/boost-1.88.0/boost-1.88.0-cmake.tar.gz',
  'dcea50f40ba1ecfc448fdf886c0165cf3e525fef2c9e3e080b9804e8117b9694'),
 ('libevent','https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz',
  '92e6de1be9ec176428fd2367677e61ceffc2ee1cb119035037a27d346b0403bb'),
]


def main():
    ROOT.mkdir(exist_ok=True)
    env=dict(os.environ,PATH=str(TOOLS)+os.pathsep+os.environ['PATH'])
    commands=[]
    def run(*args,cwd=None):
        command=list(map(str,args));commands.append(command)
        subprocess.run(command,cwd=cwd,env=env,check=True)
    sources={}
    for name,url,digest in PACKAGES:
        archive=ROOT/f'{name}.tar.gz'
        if not archive.exists():
            print('Downloading pinned',name,flush=True)
            with urllib.request.urlopen(url,timeout=120) as response: archive.write_bytes(response.read())
        assert hashlib.sha256(archive.read_bytes()).hexdigest()==digest,name
        with tarfile.open(archive) as bundle:
            members=bundle.getmembers()
            source=ROOT/members[0].name.split('/')[0]
            if not source.exists():
                for member in members:
                    assert (ROOT/member.name).resolve().is_relative_to(ROOT.resolve())
                    assert member.isfile() or member.isdir(),member.name
                bundle.extractall(ROOT)
            sources[name]=source
    core=sources['core']
    # Apply precisely one policy-only change; the normal/default path is unchanged.
    validation=core/'src/validation.cpp'
    original=validation.read_text()
    before='    constexpr unsigned int scriptVerifyFlags = STANDARD_SCRIPT_VERIFY_FLAGS;'
    after='''    // Opt-in test-network policy: still run the active consensus script flags.
    const unsigned int scriptVerifyFlags = m_pool.m_opts.require_standard
        ? STANDARD_SCRIPT_VERIFY_FLAGS
        : GetBlockScriptFlags(*m_active_chainstate.m_chain.Tip(), m_active_chainstate.m_chainman);'''
    if before in original:
        assert original.count(before)==1
        import difflib
        changed=original.replace(before,after)
        patch=''.join(difflib.unified_diff(original.splitlines(True),changed.splitlines(True),
                   fromfile='a/src/validation.cpp',tofile='b/src/validation.cpp'))
        (HERE/'core-nonstandard-policy.patch').write_text(patch)
        validation.write_text(changed)
    else: assert after in original
    cmake=TOOLS/'cmake'
    prefix=ROOT/'prefix'
    run(cmake,'-S',sources['boost'],'-B',ROOT/'boost-build','-G','Ninja',
        '-DBOOST_INCLUDE_LIBRARIES=multi_index;signals2','-DBUILD_TESTING=OFF',
        '-DBOOST_ENABLE_MPI=OFF','-DBOOST_ENABLE_PYTHON=OFF',f'-DCMAKE_INSTALL_PREFIX={prefix}')
    run(cmake,'--build',ROOT/'boost-build','--target','install','-j','8')
    run(cmake,'-S',sources['libevent'],'-B',ROOT/'libevent-build','-G','Ninja',
        '-DCMAKE_POLICY_VERSION_MINIMUM=3.5','-DCMAKE_BUILD_TYPE=Release',
        '-DEVENT__DISABLE_BENCHMARK=ON','-DEVENT__DISABLE_OPENSSL=ON',
        '-DEVENT__DISABLE_SAMPLES=ON','-DEVENT__DISABLE_REGRESS=ON',
        '-DEVENT__DISABLE_TESTS=ON','-DEVENT__LIBRARY_TYPE=STATIC',f'-DCMAKE_INSTALL_PREFIX={prefix}')
    run(cmake,'--build',ROOT/'libevent-build','--target','install','-j','8')
    build=ROOT/'core-build'
    run(cmake,'-S',core,'-B',build,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release',
        f'-DCMAKE_PREFIX_PATH={prefix}','-DENABLE_WALLET=OFF','-DENABLE_IPC=OFF',
        '-DBUILD_TESTS=OFF','-DBUILD_GUI=OFF','-DBUILD_CLI=OFF','-DBUILD_TX=OFF',
        '-DBUILD_UTIL=OFF','-DBUILD_BENCH=OFF','-DWITH_ZMQ=OFF','-DWITH_USDT=OFF')
    run(cmake,'--build',build,'--target','bitcoind','-j','8')
    binary=build/'bin/bitcoind'
    report=dict(commit=COMMIT,binary=str(binary),binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        source_archives=[dict(name=n,url=u,sha256=h) for n,u,h in PACKAGES],commands=commands,
        patch_sha256=hashlib.sha256((HERE/'core-nonstandard-policy.patch').read_bytes()).hexdigest(),
        validation_cpp_sha256=hashlib.sha256(validation.read_bytes()).hexdigest(),
        compiler=subprocess.check_output(['clang++','--version'],text=True),
        cmake=subprocess.check_output([str(cmake),'--version'],text=True))
    (HERE/'core-nonstandard-build.json').write_text(json.dumps(report,indent=2)+'\n')
    print('Built',binary,flush=True)


if __name__=='__main__':main()
