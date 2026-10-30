module example.com/skippprod

go 1.23

require example.com/unreachdep v0.0.0

replace example.com/unreachdep => ../unreachdep
