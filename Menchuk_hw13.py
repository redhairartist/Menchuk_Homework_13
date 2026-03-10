import requests
import json
import os

def get_file_scan_status(api_key, file_hash):
    """
    Функция обращается к API VirusTotal (v3) для получения отчета о файле по его хэшу.
    """
    # Формируем URL для обращения к API
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    # Настраиваем заголовки, включая передачу API-ключа для авторизации
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    try:
        # Выполняем GET-запрос
        response = requests.get(url, headers=headers)
        
        # Проверяем, нет ли ошибок (например, 401 Unauthorized или 404 Not Found)
        response.raise_for_status() 

        # Преобразуем ответ в JSON-формат
        json_data = response.json()
        return json_data

    except requests.exceptions.RequestException as error:
        print(f"[-] Произошла ошибка при выполнении запроса: {error}")
        return None

if __name__ == "__main__":
    # Получаем API-ключ из переменных окружения
    API_KEY = os.getenv("VT_API_KEY")

    if not API_KEY:
        print("[-] Ошибка: Переменная окружения VT_API_KEY не задана.")
        print("[i] Пожалуйста, прочитайте инструкцию в комментариях к коду и задайте API-ключ.")
    else:
        # Для примера используем хэш (SHA-256) безопасного тестового вируса EICAR
        test_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        
        print(f"[i] Выполняется запрос к VirusTotal для хэша: {test_hash}...")
        
        # Выполняем запрос
        result = get_file_scan_status(API_KEY, test_hash)

        if result:
            print("\n[+] Запрос успешно выполнен. Полученный JSON-ответ:")
            # Выводим полученный JSON-ответ в консоль с отступами для лучшей читаемости
            print(json.dumps(result, indent=4, ensure_ascii=False))