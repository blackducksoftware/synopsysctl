echo "CREATE OPSSIGHT"
go test synopsysctl-tests/cmd_create/createOpsSight_test.go -v -count=1 -run ".*"
echo ""

echo "START OPSSIGHT"
go test synopsysctl-tests/cmd_start/startOpsSight_test.go -v -count=1 -run ".*"
echo ""

echo "STOP OPSSIGHT"
go test synopsysctl-tests/cmd_stop/stopOpsSight_test.go -v -count=1 -run ".*"
echo ""

echo "UPDATE OPSSIGHT"
go test synopsysctl-tests/cmd_update/updateOpsSight_test.go -v -count=1 -run ".*"
echo ""

echo "UPDATE OPSSIGHT UPGRADE"
go test synopsysctl-tests/cmd_update/updateOpsSightUpgrade_test.go -v -count=1 -run ".*"
echo ""