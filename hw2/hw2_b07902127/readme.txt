Problem 5:
$python3 code5.py

一開始會顯示一個target: xxx。xxx是nonce1，根據report裡面所說，複製這個nonce1之後，輸入nonce1,nonce1作為nonce2。例如nonce為123的話，則輸入123,123。接著Enter後server會再次顯示nonce1以及hash值，並要求輸入對應的hash值。這時要注意，如果這個nonce1和前一次的nonce1不同，就表示產生時間差了，此時請直接按control c以終止程式並且重新執行。如果相同的話，就複製server給的hash值直接回傳就好。如此就能夠得到FLAG2了。最後再按control c終止程式即可。

Problem 6:
$python3 code6.py

會看到p, q, FLAG1以及RSA private key。由於第二個FLAG不容易自動化進行，因此直接把過程寫在report裡面了。

Problem 7:
$python3 code7.py

包含兩個flag，第一個會直接顯示出來。接著如果要跑第二個FLAG的話，就直接按Enter。不過由於第二個flag要DoS KDC server，因此助教測試時可能要同時跑很多個才能成功，且建議把第一個flag的code先註解掉。解果會寫入flag2_result這個檔案，如果有成功的話會看到該檔案，裡面就會有flag2的結果。
如果不想跑DoS的部分，一樣control c終止就可以了。另外在程式裡面，可以看到一段註解掉的while。這段code如果跑起來，只按control c是沒辦法跳出來的，需要長按control c或是直接用kill去終止該process。目的是為了能夠持續的DoS server以提升拿到flag的機會。
