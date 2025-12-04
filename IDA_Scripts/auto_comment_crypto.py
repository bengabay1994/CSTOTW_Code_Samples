import findcrypt3
import idc
import ida_bytes
import ida_kernwin

def main():
    print("-" * 60)
    print("Starting Auto-Comment Script for FindCrypt3...")
    try:
        plugin_instance = findcrypt3.Findcrypt_Plugin_t()
    except AttributeError:
        print("❌ Error: Could not find 'Findcrypt_Plugin_t'. This script is using https://github.com/polymorf/findcrypt-yara")
        return

    # 2. Setup paths
    # The plugin needs to know where its YARA rules are stored
    plugin_instance.user_directory = plugin_instance.get_user_directory()
    
    # 3. Prepare Memory for Scanning
    # This grabs the raw bytes from the database to match against YARA rules
    print("⏳ Reading memory segments...")
    memory, offsets = plugin_instance._get_memory()

    # 4. Compile Rules
    # Compiles the .rules files found in your plugin directory
    rules = findcrypt3.yara.compile(filepaths=plugin_instance.get_rules_files())

    # 5. Run the Scan
    print("🔍 Scanning for crypto constants (this might take a moment)...")
    # This returns a list of lists: [[Address, Type, Name, ...], ...]
    results = plugin_instance.yarasearch(memory, offsets, rules)

    # 6. Apply Comments
    count = 0
    print(f"📝 Applying comments to {len(results)} detected locations...")
    
    for item in results:
        exact_address = item[0]   # The exact byte where the constant starts
        algo_name = item[2]       # The name (e.g., "SHA256_Constants...")
        
        # If the constant is in the middle of an instruction (Tail Byte),
        # we move the comment to the 'Head' (start) of that instruction so it is visible.
        head_address = ida_bytes.get_item_head(exact_address)
        
        # Add the comment
        idc.set_cmt(head_address, algo_name, 1)
        count += 1

    print("-" * 60)
    print(f"✅ Success! Added {count} comments to your disassembly.")
    print("💡 Tip: If you see rename byte errors text above, ignore it. It is just renaming errors from the yarasearch function.")

if __name__ == "__main__":
    main()