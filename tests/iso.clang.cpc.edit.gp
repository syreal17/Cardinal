set terminal jpeg enhanced
set output "iso.clang.cpc.edit.jpg"
set yrange [0:1]
plot "iso.clang.cpc.edit.dat" u 2:xticlabel(1) t 'Burg' w lines,\
	"iso.clang.cpc.edit.dat" u 3:xticlabel(1) t 'Treecc' w lines,\
	"iso.clang.cpc.edit.dat" u 4:xticlabel(1) t 'Lua' w lines,\
	"iso.clang.cpc.edit.dat" u 5:xticlabel(1) t 'Sqlite3' w lines
