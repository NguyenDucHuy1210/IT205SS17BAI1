raw_logs = []
processed_logs = []


def input_raw_data():
    global raw_logs
    str_input = input("Nhập chuỗi log thô (cách nhau bởi dấu ;): ")
    table = str_input.maketrans("", "", "!@#$")
    str_input = str_input.translate(table)
    new_list = str_input.split(";")
    raw_logs.extend(new_list)
    print(f"Đã làm sạch và lưu {len(new_list)} dòng log vào hệ thống.")


def warning_raw_logs():
    global processed_logs
    global raw_logs
    count = 0
    processed_logs.clear()
    for log in raw_logs:
        if "ERROR" in log or "CRITICAL" in log:
            processed_logs.append(log)
            count += 1
    print(f"Tìm thấy {count} cảnh báo nguy hiểm:")
    for pro_log in processed_logs:
        print(f"- {pro_log}")


def clean_logs(log_text):
    table = str.maketrans("", "", "!@#$")
    cleaned_text = log_text.translate(table)

    logs = [log.strip() for log in cleaned_text.split(";") if log.strip()]
    return logs


def filter_danger_logs():
    global raw_logs

    danger_logs = [
        log for log in raw_logs
        if "ERROR" in log.upper() or "CRITICAL" in log.upper()]
    return danger_logs
def mask_ip_logs(logs):
    masked_logs = []
    for log in logs:
        words = log.split()
        for i in range(len(words)):
            if "." in words[i]:
                parts = words[i].split(".")
                if len(parts) == 4:
                    words[i] = ".".join(parts[:2]) + ".*.*"
        masked_logs.append(" ".join(words))
    return masked_logs


while True:
    print("""
============= SECURITY LOG ANALYZER =============
1. Nhập và làm sạch dữ liệu Log thô
2. Lọc các Log cảnh báo mức độ cao (ERROR/CRITICAL)
3. Mã hóa địa chỉ IP (Masking)
4. Đóng hệ thống
=================================================
""")
    while True:
        try:
            choice = int(input("Chọn chức năng (1-4): "))
            if choice >= 1 and choice <= 4:
                break
            else:
                print("Chọn từ 1 - 4")
        except ValueError:
            print("Chọn từ 1 - 4")
    match choice:
        case 1:
            input_raw_data()

        case 2:
            warning_raw_logs()
        case 3:
            print("--- MÃ HÓA IP ---")
            if not raw_logs:
                print("Chưa có dữ liệu log, vui lòng thực hiện chức năng 1")
                continue
            if not processed_logs:
                print("Chưa có log cảnh báo để mã hóa.")
                continue
            safe_logs = mask_ip_logs(processed_logs)
            print("Báo cáo log an toàn:")
            for index, log in enumerate(safe_logs, start=1):
                print(f"{index}. {log}")
        case 4:
            print("Thoát chương trình!")
            break
