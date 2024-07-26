// C++ STL headers
#include <iostream>
#include <vector>
#include <stdexcept>
#include <system_error>
// Linux system headers
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <grp.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
// My headers
#include "util.h"
#include "log.h"
#include <seccomp.h>
#include <errno.h>

using namespace std;
using namespace util;

SimpleLogStream logger;  // Rename log to logger

struct Options
{
    unsigned int timeout_ms;
    uid_t uid;
    gid_t gid;
    bool debug;
    bool mount_proc;
    bool mount_sys;
    vector<string> extra_mounts;
    bool mount_program;

    Options()
    {
        timeout_ms = 0;
        uid = getuid();
        gid = getgid();
        debug = false;
        mount_proc = false;
        mount_sys = false;
        mount_program = true;
    }

    Options(const Options& o)
     : timeout_ms{o.timeout_ms},
       uid{o.uid}, gid{o.gid}, debug{o.debug},
       mount_proc{o.mount_proc}, mount_sys{o.mount_sys},
       extra_mounts{o.extra_mounts}, mount_program{o.mount_program}
    {
    }

    static void Usage(const char* prog);
    static Options Parse(int& argc, char**& argv);
    void Log();
};

void Options::Usage(const char* prog)
{
    cerr << "Usage: " << prog << " [OPTIONS] COMMAND\n";
    cerr << "\n";
    cerr << "OPTIONS:\n";
    cerr << "    -d         Enable debug messages\n";
    cerr << "    -t T       Terminate program after T milliseconds\n";
    cerr << "    -u uid     Run command with user uid\n";
    cerr << "    -g gid     Run command with group gid\n";
    cerr << "    -p         Mount /proc\n";
    cerr << "    -s         Mount /sys\n";
    cerr << "    -m path    Mount path under /mnt/`basename path`\n";
    cerr << "    -M         Do not mount program\n";
    cerr << "\n";
    cerr << "The -m option can be repeated to mount multiple paths.\n";
    cerr << "If the -M option is not specified, the program is mounted at\n";
    cerr << "/program which is useful for programs that are not installed\n";
    cerr << "in standard locations such as /bin or /usr/bin\n";
    cerr << "\n";
}

Options Options::Parse(int& argc, char**& argv)
{
    int opt;
    Options options;
    while ((opt = getopt(argc, argv, "+dt:u:g:psm:M")) != -1) {
        switch (opt) {
            case 'd':   options.debug = true;   break;
            case 't':
            {
                int t = atoi(optarg);
                if (t > 0)
                {
                    options.timeout_ms = t;
                }
                else
                {
                    throw runtime_error("Error parsing options: timeout value must be positive");
                }
                break;
            }
            case 'u':   options.uid = atoi(optarg);     break;
            case 'g':   options.gid = atoi(optarg);     break;
            case 'p':   options.mount_proc = true;      break;
            case 's':   options.mount_sys = true;       break;
            case 'm':   options.extra_mounts.push_back(optarg); break;
            case 'M':   options.mount_program = false;  break;
            default:
            {
                Usage(argv[0]);
                throw runtime_error("Error parsing options: unknown option");
            }
        }
    }
    argc -= optind;
    argv += optind;
    return options;
}

void Options::Log()
{
    logger << boolalpha;
    logger << "Options:\n";
    logger << "  Timeout: " << timeout_ms << " ms\n";
    logger << "  UID: " << uid << "\n";
    logger << "  GID: " << gid << "\n";
    logger << "  Debug: " << debug << "\n";
    logger << "  Mount /proc: " << mount_proc << "\n";
    logger << "  Mount /sys: " << mount_sys << "\n";
    logger << "  Extra mounts (" << extra_mounts.size() << "):\n";
    for (auto& x : extra_mounts)
    {
        logger << "    " << x << "\n";
    }
    logger << "  Mount program: " << mount_program << "\n";
}

class Sandbox
{
  public:
    explicit Sandbox(Options options_) : options{options_}, ctor_pid{getpid()}
    {
        logger << "\n[" << getpid() << "] Sandbox():\n";
        rootfs = CreateTempFolder("/tmp/sandbox_");
        ChangeMode(rootfs, 0755);
        logger << " rootfs = " << rootfs << "\n";
        CreatePrivateMount(rootfs);
        for (auto& folder : always_mount)
        {
            if (PathExists(folder))
            {
                string mount_point = rootfs + folder;
                logger << " Creating folder " << mount_point << "\n";
                CreateFolder(mount_point);
            }
        }
        logger << " Creating folder " << rootfs + "/mnt" << "\n";
        CreateFolder(rootfs + "/mnt");
        for (auto& path : options.extra_mounts)
        {
            string mount_point = rootfs + "/mnt/" + BaseName(path);
            if (IsDirectory(path))
            {
                logger << " Creating folder " << mount_point << "\n";
                CreateFolder(mount_point);
            }
            if (IsRegularFile(path))
            {
                logger << " Creating file " << mount_point << "\n";
                ofstream pfs(mount_point);
                pfs.close();
            }
        }
        if (options.mount_program)
        {
            program_mount_point = rootfs + program_path;
            logger << " Creating program mount point " << program_mount_point << "\n";
            ofstream pfs(program_mount_point);
            pfs.close();
        }
    }

    ~Sandbox()
    {
        if (getpid() == ctor_pid)
        {
            try { // We don't want to throw any exceptions from a dtor
                logger << "\n[" << getpid() << "] ~Sandbox():\n";
                logger << " ctor_pid = " << ctor_pid << "\n";
                if (options.mount_program)
                {
                    logger << " Deleting " << program_mount_point << "\n";
                    DeleteFile(program_mount_point);
                }
                for (auto& path : options.extra_mounts)
                {
                    string mount_point = rootfs + "/mnt/" + BaseName(path);
                    logger << " Deleting " << mount_point << "\n";
                    if (IsDirectory(mount_point))
                    {
                        DeleteFolder(mount_point);
                    }
                    if (IsRegularFile(mount_point))
                    {
                        DeleteFile(mount_point);
                    }
                }
                logger << " Deleting " << rootfs + "/mnt" << "\n";
                DeleteFolder(rootfs + "/mnt");
                for (auto& folder : always_mount)
                {
                    string mount_point = rootfs + folder;
                    if (PathExists(mount_point))
                    {
                        logger << " Deleting " << mount_point << "\n";
                        DeleteFolder(mount_point);
                    }
                }
                logger << " Unmounting rootfs @ " << rootfs << "\n";
                Unmount(rootfs);
                logger << " Deleting rootfs @ " << rootfs << "\n";
                DeleteFolder(rootfs);
                logger << "Finished cleanup\n";
            }
            catch (const exception& e) {
                logger << "~Sandbox - error cleaning up: " << e.what() << "\n";
            }
        }
    }

    void RunCommand(char* args[])
    {
        ForkCallWait([&]() { unshare_mount(args); });
    }

  private:
    static vector<string> always_mount;
    Options options;
    string rootfs;
    pid_t ctor_pid;
    string program_mount_point;
    static constexpr const char* program_path = "/program";

    void unshare_mount(char* args[])
    {
        try {
            logger << "\n[" << getpid() << "] unshare_mount():\n";
            int flags = CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS |
                        CLONE_NEWNET | CLONE_NEWPID | CLONE_SYSVSEM;
            // TODO: Add CLONE_NEWCGROUP for Linux 4.6+
            Unshare(flags);
            MarkMountPointPrivate("/");

            for (auto& folder : always_mount)
            {
                if (PathExists(folder))
                {
                    string mount_point = rootfs + folder;
                    logger << " Mounting folder " << folder << " at " << mount_point << "\n";
                    BindMount(folder, mount_point);
                }
            }

            for (auto& path : options.extra_mounts)
            {
                string mount_point = rootfs + "/mnt/" + BaseName(path);
                if (PathExists(mount_point))
                {
                    logger << " Mounting " << path << " at " << mount_point << "\n";
                    BindMount(path, mount_point);
                }
            }

            if (options.mount_program)
            {
                logger << " Mounting program " << args[0] << " at " << program_mount_point << "\n";
                BindMount(args[0], program_mount_point);
                args[0] = strdup(program_path);
            }

            ForkCallWait([&]() { chroot_run(args); });

            logger << "\n Unmounting...\n";
            if (options.mount_program)
            {
                logger << " Unmounting " << program_mount_point << "\n";
                Unmount(program_mount_point);
            }

            for (auto& path : options.extra_mounts)
            {
                string mount_point = rootfs + "/mnt/" + BaseName(path);
                if (PathExists(mount_point))
                {
                    logger << " Unmounting " << mount_point << "\n";
                    Unmount(mount_point);
                }
            }

            for (auto& folder : always_mount)
            {
                string mount_point = rootfs + folder;
                if (PathExists(mount_point))
                {
                    logger << " Unmounting " << mount_point << "\n";
                    Unmount(mount_point);
                }
            }
            logger << "[" << getpid() << "] Finished!\n";
        }
        catch (exception& e) {
            logger << "Exception in unshare_mount(): " << e.what() << "\n";
            exit(EXIT_FAILURE);
        }
    }

    void chroot_run(char* args[])
    {
        try {
            logger << "\n[" << getpid() << "] chroot_run():\n";
            Chroot(rootfs);
            Chdir("/");

            if (options.mount_proc)
            {
                CreateFolder("/proc");
                MountSpecialFileSystem("/proc", "proc");
            }
            if (options.mount_sys)
            {
                CreateFolder("/sys");
                MountSpecialFileSystem("/sys", "sysfs");
            }

            setup_seccomp(); // enable seccomp. todo add option for this

            if (options.timeout_ms > 0)
            {
                ForkExecWaitTimeout(args, [&]() { drop_privilege(); }, options.timeout_ms);
            }
            else
            {
                ForkExecWait(args, [&]() { drop_privilege(); });
            }

            if (options.mount_sys)
            {
                Unmount("/sys");
                DeleteFolder("/sys");
            }
            if (options.mount_proc)
            {
                Unmount("/proc");
                DeleteFolder("/proc");
            }
            logger << "\n[" << getpid() << "] chroot_run() finished.\n";
        }
        catch (exception& e) {
            logger << "Exception in chroot_run(): " << e.what() << "\n";
            exit(EXIT_FAILURE);
        }
    }

    void drop_privilege(void)
    {
        try
        {
            if (setgroups(0, nullptr) < 0)
            {
                throw system_error(errno, system_category(),
                                   "drop_privilege, setgroups() failed");
            }
            if (setgid(options.gid) < 0)
            {
                throw system_error(errno, system_category(),
                                   "drop_privilege, setgid() failed");
            }
            if (setuid(options.uid) < 0)
            {
                throw system_error(errno, system_category(),
                                   "drop_privilege, setuid() failed");
            }
        }
        catch(exception& e)
        {
            logger << "Error: " << e.what() << "\n";
            exit(EXIT_FAILURE);
        }
    }

    void setup_seccomp()
    {
        scmp_filter_ctx ctx;
        ctx = seccomp_init(SCMP_ACT_KILL); // default action: kill process

        // essential system calls
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(futex), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);

        // file-related system calls
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 1, SCMP_A1(SCMP_CMP_EQ, O_RDONLY));
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lstat), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(readlink), 0);

        // process-related system calls
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 1, SCMP_A0(SCMP_CMP_MASKED_EQ, CLONE_VM, CLONE_VM));
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fork), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(vfork), 0);

        // network-related system calls
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0);

        if (seccomp_load(ctx) != 0) {
            std::cerr << "Failed to load seccomp filter: " << strerror(errno) << std::endl;
            seccomp_release(ctx);
            exit(EXIT_FAILURE);
        }

        seccomp_release(ctx);
    }
};

vector<string> Sandbox::always_mount{ "/bin", "/etc", "/lib", "/lib32", "/lib64", "/usr" };

int main(int argc, char* argv[])
{
    char* prog = argv[0];
    Options options = Options::Parse(argc, argv);
    if (options.debug)
    {
        logger.SetOutput(&cerr);
    }
    if (argc < 1)
    {
        cerr << "Error: missing command to execute!\n\n";
        Options::Usage(prog);
        exit(EXIT_FAILURE);
    }
    if (options.uid == 0 || options.gid == 0)
    {
        cerr << "Error: could not determine a non-root uid/gid to drop privileges.\n\n";
        cerr << "You should either:\n";
        cerr << "- run this program as a set-user-id binary run by a non-root user\n";
        cerr << "- or specify uid and gid through -u and -g options\n\n";
        Options::Usage(prog);
        exit(EXIT_FAILURE);
    }
    options.Log();
    Sandbox s {options};
    s.RunCommand(argv);
    return 0;
}
