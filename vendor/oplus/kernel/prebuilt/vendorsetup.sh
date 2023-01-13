links_dir="$(dirname $(readlink -e "${BASH_SOURCE[0]}"))/${CHIPSET_COMPANY}"
soc_common_links_path="${links_dir}/common/kernel_links"
soc_platform_links_path="${links_dir}/${OPLUS_VND_BUILD_PLATFORM}/kernel_links"

failed_links=""
successful_links=""
existed_links=""
count=0
if [[ -f "$soc_common_links_path" && "$soc_platform_links_path" ]];then
  total_links=$(cat $soc_common_links_path $soc_platform_links_path | wc -l)
  for i in $(cat $soc_common_links_path $soc_platform_links_path);do
    src=$(echo $i | awk -F:: '{print $1}')
    dest=$(echo $i | awk -F:: '{print $2}')
    if [ -e "$dest" ];then
      source=$(readlink  -f $dest)
      abs_src=$(readlink  -f $src)
      if [ $source == $abs_src ];then
          existed_links="$existed_links $i"
          continue
      else
          rm -rf $dest
      fi
    fi
    if [[ -e $src && ! -e $dest ]];then
      mkdir -p $(dirname $dest)
      ln -srf $src $dest
      successful_links="$successful_links $i"
      count=$(($count + 1))
    else
      failed_links="$failed_links $i"
    fi
  done
  if [ ! -z "$failed_links" ];then
    echo "*****Could not create symlink*******"
    echo $failed_links | sed 's/[[:space:]]/\n/g'
    echo "****************END******************"
  fi
  echo "Created $count symlinks out of $total_links mapped links.."
  if [ ! -z "$successful_links" ];then
    echo "*****Created symlink*******"
    echo $successful_links | sed 's/[[:space:]]/\n/g'
    echo "****************END******************"
  fi
  echo "*****Existed symlink*******"
  if [ ! -z "$existed_links" ];then
    echo $existed_links | sed 's/[[:space:]]/\n/g'
    echo "****************END******************"
  fi
fi

# Remove dangling symlinks
if [ ! -d ./vendor/qcom/defs ]; then
    return
fi
symlinks=$(find ./vendor/qcom/defs -type l)
for symlink in $symlinks;do
dest_link=$(readlink -f $symlink)
if [[ ! ( -f $dest_link || -d $dest_link ) ]];then
echo "Removing dangling symlink $symlink"
rm -rf  $symlink
fi
done
