LUA_PATH=/usr/local/include/snort/lua/\?.lua\;\;
SNORT_LUA_PATH=/usr/local/etc/snort
export LUA_PATH=/usr/local/include/snort/lua/\?.lua\;\;
export SNORT_LUA_PATH=/usr/local/etc/snort
sudo sh -c "echo 'LUA_PATH=/usr/local/include/snort/lua/\?.lua\;\;' >> /etc/environment"
sudo sh -c "echo 'SNORT_LUA_PATH=/usr/local/etc/snort' >> /etc/environment"