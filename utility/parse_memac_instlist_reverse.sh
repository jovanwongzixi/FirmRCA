# python3 decode_memacbin.py | awk '{
#     if ($0 ~ /pc *= *[0-9]+/) {
#         pc_val = $0
#         sub(/.*pc *= */, "", pc_val)   # remove everything before number
#         sub(/,.*/, "", pc_val)         # remove everything after number
#         printf "0x%x\n", pc_val
#     }
# }' | tac > numbers.txt
python3 decode_memacbin.py | awk '/instruction/ {
    pc_val = $0
    sub(/.*pc *= */, "", pc_val)   # strip everything before pc number
    sub(/,.*/, "", pc_val)         # strip everything after pc number
    printf "0x%x\n", pc_val
}' | tac > instlist.reverse
