# Do not use this script directly, see monkey.sh

start
p srand($seed)
set monkey_rate = 0x0fffffff
continue
if ($_siginfo)
    quit $_siginfo.si_signo
end
quit 0
