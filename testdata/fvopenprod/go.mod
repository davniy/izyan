module example.com/fvopenprod

go 1.23

require example.com/dep v1.0.0

replace example.com/dep => ../dep

require example.com/dep2 v0.0.0

replace example.com/dep2 => ../dep2
