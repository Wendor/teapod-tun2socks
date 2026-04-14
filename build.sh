#!/usr/bin/env bash
# ============================================================================
# build.sh — Сборка teapod-tun2socks AAR через gomobile bind
# ============================================================================
# Этот скрипт компицирует Go-код в Android .aar библиотеку
# для всех основных Android-архитектур.
#
# Требования:
#   - Go 1.21+
#   - gomobile (go install golang.org/x/mobile/cmd/gomobile@latest)
#   - Android NDK (переменная ANDROID_NDK_HOME или ANDROID_HOME)
#   - Java 8+ (JAVA_HOME)
#
# Использование:
#   ./build.sh              # Собрать для всех архитектур
#   ./build.sh arm64        # Только arm64-v8a
#   ./build.sh clean        # Очистить выходные файлы
# ============================================================================

set -euo pipefail

# --- Конфигурация ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_MODULE_DIR="${SCRIPT_DIR}/go"
OUTPUT_DIR="${SCRIPT_DIR}/output"
AAR_NAME="teapod-tun2socks"
MIN_ANDROID_API=29

# Архитектуры для сборки (gomobile targets)
ARCH_ARM64="arm64"   # -> arm64-v8a
ARCH_ARM="arm"       # -> armeabi-v7a
ARCH_X86_64="amd64"  # -> x86_64

ALL_ARCH="${ARCH_ARM64},${ARCH_ARM},${ARCH_X86_64}"

# --- Проверка зависимостей ---

check_prerequisites() {
    echo "=== Проверка зависимостей ==="

    if ! command -v go &> /dev/null; then
        echo "ОШИБКА: go не найден. Установите Go 1.21+"
        exit 1
    fi

    GO_VERSION=$(go version | awk '{print $3}')
    echo "Go версия: ${GO_VERSION}"

    if ! command -v gomobile &> /dev/null; then
        echo "gomobile не найден. Устанавливаю..."
        go install golang.org/x/mobile/cmd/gomobile@latest
        go install golang.org/x/mobile/cmd/gobind@latest
    fi

    GOMOBILE_VERSION=$(gomobile version 2>/dev/null || echo "unknown")
    echo "gomobile: ${GOMOBILE_VERSION}"

    # Проверка NDK
    if [ -n "${ANDROID_NDK_HOME:-}" ] && [ -d "${ANDROID_NDK_HOME}" ]; then
        echo "ANDROID_NDK_HOME: ${ANDROID_NDK_HOME}"
    elif [ -n "${ANDROID_HOME:-}" ] && [ -d "${ANDROID_HOME}/ndk" ]; then
        ANDROID_NDK_HOME=$(ls -d "${ANDROID_HOME}/ndk"/* 2>/dev/null | head -1)
        if [ -n "${ANDROID_NDK_HOME}" ]; then
            export ANDROID_NDK_HOME
            echo "NDK найден через ANDROID_HOME: ${ANDROID_NDK_HOME}"
        else
            echo "ПРЕДУПРЕЖДЕНИЕ: NDK не найден. Установите Android NDK или задайте ANDROID_NDK_HOME"
        fi
    else
        echo "ПРЕДУПРЕЖДЕНИЕ: ANDROID_NDK_HOME не задан. gomobile может не найти NDK."
        echo "Рекомендуется: export ANDROID_NDK_HOME=\$HOME/Android/Sdk/ndk/<version>"
    fi

    if ! command -v javac &> /dev/null; then
        echo "ПРЕДУПРЕЖДЕНИЕ: javac не найден. Убедитесь что JAVA_HOME настроен."
    fi

    echo ""
}

# --- Очистка ---

clean() {
    echo "=== Очистка ==="
    rm -rf "${OUTPUT_DIR}"
    rm -rf "${GO_MODULE_DIR}/go.sum"
    echo "Очищено."
}

# --- Загрузка зависимостей ---

fetch_deps() {
    echo "=== Загрузка Go-зависимостей ==="
    cd "${GO_MODULE_DIR}"

    go mod download
    go mod tidy

    echo "Зависимости загружены."
    echo ""
}

# --- Сборка AAR ---

build_aar() {
    local arches="${1:-$ALL_ARCH}"

    echo "=== Сборка AAR ==="
    echo "Архитектуры: ${arches}"
    echo "Минимальный Android API: ${MIN_ANDROID_API}"
    echo "Целевая директория: ${OUTPUT_DIR}"
    echo ""

    mkdir -p "${OUTPUT_DIR}"

    cd "${GO_MODULE_DIR}"

    echo "Запуск gomobile bind..."
    echo "Архитектуры Go: ${arches}"
    echo "Target: android/${arches//,/,android/}"
    echo "Из директории: $(pwd)"

    # Выполняем gomobile bind
    # Добавляем -v для отладки
    gomobile bind \
        -v \
        -target="android/${arches//,/,android/}" \
        -androidapi="${MIN_ANDROID_API}" \
        -o "${OUTPUT_DIR}/${AAR_NAME}.aar" \
        ./...

    if [ ! -f "${OUTPUT_DIR}/${AAR_NAME}.aar" ]; then
        echo "ОШИБКА: Базовый Go AAR не создан по пути ${OUTPUT_DIR}/${AAR_NAME}.aar"
        echo "Проверка содержимого выходной папки:"
        ls -la "${OUTPUT_DIR}"
        exit 1
    fi

    # 2. Собираем Kotlin обёртку и объединяем с Go AAR для каждой архитектуры
    echo ""
    echo "=== Сборка Kotlin обёртки и создание релизных AAR ==="

    local KOTLIN_DIR="${SCRIPT_DIR}/kotlin"
    cd "${KOTLIN_DIR}"

    if [ ! -f "./gradlew" ]; then
        echo "ПРЕДУПРЕЖДЕНИЕ: gradlew не найден. Пытаюсь создать..."
        # Ищем gradle в системе для создания wrapper
        local system_gradle=""
        if command -v gradle &> /dev/null; then
            system_gradle="gradle"
        else
            system_gradle=$(find ~/.gradle/wrapper/dists -name "gradle" -type f -path "*/bin/gradle" 2>/dev/null | head -1)
        fi
        
        if [ -n "${system_gradle}" ]; then
            "${system_gradle}" wrapper
        else
            echo "ОШИБКА: Gradle не найден! Установите Gradle или создайте wrapper вручную."
            exit 1
        fi
    fi

    # Список архитектур Android для финальной упаковки
    local ANDROID_ARCHES=()
    if [[ "${arches}" == *"${ARCH_ARM64}"* ]]; then ANDROID_ARCHES+=("arm64-v8a"); fi
    if [[ "${arches}" == *"${ARCH_ARM}"* ]]; then ANDROID_ARCHES+=("armeabi-v7a"); fi
    if [[ "${arches}" == *"${ARCH_X86_64}"* ]]; then ANDROID_ARCHES+=("x86_64"); fi
    
    # Режим сборки: только поархитектурные AAR
    echo "--- Очистка перед сборкой ---"
    ./gradlew clean --no-daemon

    # Сборка для каждой выбранной архитектуры
    for arch in "${ANDROID_ARCHES[@]}"; do
        echo ""
        echo "--- Сборка AAR для архитектуры: ${arch} ---"
        # Передаём параметр arch в Gradle
        ./gradlew assembleFatAar -PtargetArch="${arch}" --no-daemon
    done

    # 3. Копируем результаты в output
    echo ""
    echo "=== Копирование результатов в ${OUTPUT_DIR} ==="
    
    # Считываем версию из gradle.properties
    local version
    version=$(grep "libraryVersion" "${KOTLIN_DIR}/gradle.properties" | cut -d'=' -f2 | tr -d ' \r\n')
    [ -z "${version}" ] && version="1.0.0"

    # Удаляем временный базовый Go AAR из output
    rm -f "${OUTPUT_DIR}/${AAR_NAME}.aar"
    
    local GRADLE_OUTPUT_DIR="${KOTLIN_DIR}/build/outputs/fat-aar"
    
    # Копируем только поархитектурные библиотеки
    for arch in "${ANDROID_ARCHES[@]}"; do
        local arch_aar="${GRADLE_OUTPUT_DIR}/${AAR_NAME}-${arch}-${version}.aar"
        if [ -f "${arch_aar}" ]; then
            cp "${arch_aar}" "${OUTPUT_DIR}/"
            local size
            size=$(du -h "${OUTPUT_DIR}/${AAR_NAME}-${arch}-${version}.aar" | cut -f1)
            echo "AAR для ${arch}: ${OUTPUT_DIR}/${AAR_NAME}-${arch}-${version}.aar (${size})"
        fi
    done

    echo ""
    echo "=== Сборка завершена ==="
}


# --- Публикация на GitHub ---

push_to_github() {
    echo "=== Публикация на GitHub ==="

    if ! command -v gh &> /dev/null; then
        echo "ОШИБКА: gh CLI не найден. Установите его: brew install gh"
        exit 1
    fi

    # Считываем версию из gradle.properties
    local version
    version=$(grep "libraryVersion" "kotlin/gradle.properties" | cut -d'=' -f2 | tr -d ' \r\n')
    [ -z "${version}" ] && version="1.0.0"
    local tag="v${version}"

    echo "Версия: ${version}"
    echo "Тег: ${tag}"

    # Проверяем наличие собранных файлов
    local files=()
    # Ищем все AAR с текущей версией
    for f in "${OUTPUT_DIR}"/*"-${version}.aar"; do
        if [ -f "$f" ]; then
            files+=("$f")
        fi
    done

    # Добавляем sources.jar если он есть
    local sources_jar="${OUTPUT_DIR}/${AAR_NAME}-sources.jar"
    if [ -f "${sources_jar}" ]; then
        files+=("${sources_jar}")
    fi

    if [ "${#files[@]}" -eq 0 ]; then
        echo "ОШИБКА: Файлы для публикации не найдены в ${OUTPUT_DIR}. Сначала запустите сборку: ./build.sh"
        exit 1
    fi

    echo "Файлы для загрузки:"
    for f in "${files[@]}"; do
        echo "  - $(basename "$f")"
    done
    echo ""

    # Создаем релиз и загружаем файлы
    # --generate-notes автоматически создаст описание релиза на основе коммитов
    gh release create "${tag}" "${files[@]}" \
        --title "Release ${tag}" \
        --generate-notes

    echo ""
    echo "=== Публикация завершена ==="
}


# --- Вывод информации ---

print_info() {
    # Считываем версию из gradle.properties
    local version
    version=$(grep "libraryVersion" "kotlin/gradle.properties" | cut -d'=' -f2 | tr -d ' \r\n')
    [ -z "${version}" ] && version="1.0.0"

    echo ""
    echo "=========================================================="
    echo " teapod-tun2socks AAR v${version} — Информация"
    echo "=========================================================="
    echo ""
    echo "Выходные файлы в директории: ${OUTPUT_DIR}/"
    echo "  - ${AAR_NAME}-arm64-v8a-${version}.aar"
    echo "  - ${AAR_NAME}-armeabi-v7a-${version}.aar"
    echo "  - ${AAR_NAME}-x86_64-${version}.aar"
    echo ""
    echo "Каждый AAR содержит:"
    echo "  ✅ jni/<arch>/libgojni.so — Go JNI библиотека для конкретной архитектуры"
    echo "  ✅ classes.jar — Go классы + Kotlin классы"
    echo ""
    echo "Подключение в build.gradle хост-проекта:"
    echo ""
    echo "  dependencies {"
    echo "      // Пример для arm64"
    echo "      implementation(files(\"libs/${AAR_NAME}-arm64-v8a-${version}.aar\"))"
    echo "  }"
    echo ""
    echo "Или используйте splits в Android Gradle Plugin для автоматического выбора."
    echo "=========================================================="
}

# --- Главная функция ---

main() {
    local command="${1:-all}"

    case "${command}" in
        clean)
            clean
            ;;
        deps)
            fetch_deps
            ;;
        push)
            push_to_github
            ;;
        arm64)
            check_prerequisites
            fetch_deps
            # Собираем только arm64-v8a
            build_aar "${ARCH_ARM64}"
            ;;
        arm)
            check_prerequisites
            fetch_deps
            # Собираем только armeabi-v7a
            build_aar "${ARCH_ARM}"
            ;;
        x86_64)
            check_prerequisites
            fetch_deps
            # Собираем только x86_64
            build_aar "${ARCH_X86_64}"
            ;;
        all)
            check_prerequisites
            fetch_deps
            build_aar "${ALL_ARCH}"
            print_info
            ;;
        *)
            echo "Использование: $0 {all|arm64|arm|x86_64|push|deps|clean}"
            echo ""
            echo "  all      — собрать все архитектуры (архитектурно-зависимые AAR)"
            echo "  arm64    — только arm64-v8a"
            echo "  arm      — только armeabi-v7a"
            echo "  x86_64   — только x86_64"
            echo "  push     — опубликовать собранные файлы в GitHub Release (v1.0.x)"
            echo "  deps     — загрузить Go-зависимости"
            echo "  clean    — удалить выходные файлы"
            exit 1
            ;;
    esac
}

main "$@"
