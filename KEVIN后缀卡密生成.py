import random
import string

def generate_license_keys(count, suffix="KEVIN"):
    """
    生成指定数量的唯一卡密
    
    参数:
        count: 生成卡密数量
        suffix: 卡密后缀，默认为"KEVIN"
    """
    generated_keys = set()
    
    while len(generated_keys) < count:
        # 生成随机部分：10位数字和字母混合
        random_part = ''.join(random.choices(
            string.ascii_uppercase + string.digits, 
            k=10
        ))
        
        # 组合成完整卡密
        license_key = f"{random_part}{suffix}"
        generated_keys.add(license_key)
    
    return list(generated_keys)

def save_to_file(keys, filename="key.txt"):
    """将卡密保存到文件（不带序号）"""
    with open(filename, 'w', encoding='utf-8') as f:
        for key in keys:
            f.write(f"{key}\n")
    print(f"✅ 已生成 {len(keys)} 个卡密并保存到 {filename}")

def display_preview(keys, preview_count=10):
    """显示前几个卡密作为预览"""
    print(f"\n📋 前{preview_count}个卡密预览:")
    for i, key in enumerate(keys[:preview_count], 1):
        print(f"  {key}")

def main():
    print("🎯 卡密生成工具")
    print("=" * 30)
    
    try:
        # 获取用户输入
        count = int(input("请输入要生成的卡密数量: "))
        suffix = input("请输入卡密后缀 (默认KEVIN): ").strip() or "KEVIN"
        
        if count <= 0:
            print("❌ 数量必须大于0")
            return
        
        print(f"\n🔄 正在生成 {count} 个卡密...")
        
        # 生成卡密
        license_keys = generate_license_keys(count, suffix)
        
        # 显示预览
        display_preview(license_keys)
        
        # 保存到文件（不带序号）
        save_to_file(license_keys)
        
        # 统计信息
        print(f"\n📊 生成统计:")
        print(f"   - 总数量: {len(license_keys)}")
        print(f"   - 后缀: {suffix}")
        print(f"   - 格式: 10位随机字符 + {suffix}")
        
    except ValueError:
        print("❌ 请输入有效的数字")
    except Exception as e:
        print(f"❌ 发生错误: {e}")

# 简洁版本（一行命令风格）
def quick_generate(count=100, suffix="KEVIN", filename="key.txt"):
    """快速生成卡密"""
    keys = set()
    
    while len(keys) < count:
        key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10)) + suffix
        keys.add(key)
    
    # 保存到文件（不带序号）
    with open(filename, "w") as f:
        for key in keys:
            f.write(key + "\n")
    
    print(f"✅ 已生成 {len(keys)} 个唯一卡密到 {filename}")
    return list(keys)

if __name__ == "__main__":
    print("选择模式:")
    print("1. 交互模式")
    print("2. 快速生成100个")
    print("3. 自定义快速生成")
    
    choice = input("请选择 (1/2/3): ").strip()
    
    if choice == "2":
        quick_generate()
    elif choice == "3":
        count = int(input("生成数量: "))
        suffix = input("后缀 (默认KEVIN): ").strip() or "KEVIN"
        quick_generate(count, suffix)
    else:
        main()