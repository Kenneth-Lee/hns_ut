TARGET_DIR=../htsat_kernel/drivers/net/ethernet/hisilicon/

hns_enet.ut: hns_enet.ut.c $(TARGET_DIR)/hns_enet.c ut.c
	gcc -O0 -g -I general_stub -I $(TARGET_DIR) $< -o $@

test: hns_enet.ut
	@./hns_enet.ut 2> ut.log
	@!(sed '/^[^0]/d' ut.log |addr2line -e hns_enet.ut |grep -v "ut/ut.c")

clean:
	@rm -f *.ut *.o

.PHONY: clean test
