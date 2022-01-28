# Do not use this script directly, see monkey.sh

start
p srand($seed)
set monkey_rate = 0x0fffffff
continue
if ($_siginfo)
    set $signo = $_siginfo.si_signo
    if ($rip < 0x7f00000000000000)
        quit $signo
    end
end
quit 0
