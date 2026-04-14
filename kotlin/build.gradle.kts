plugins {
    id("com.android.library") version "8.7.3"
    id("org.jetbrains.kotlin.android") version "2.1.0"
}

android {
    namespace = "com.teapodstream.tun2socks"
    compileSdk = 29

    defaultConfig {
        minSdk = 29

        // ProGuard rules для потребителей библиотеки
        consumerProguardFiles("proguard-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    kotlinOptions {
        jvmTarget = "1.8"
    }
}

dependencies {
    // Сгенерированный Go AAR — собирается командой ./build.sh из корня проекта.
    // Используем compileOnly для компиляции (Kotlin код использует Go классы)
    compileOnly(files("../output/teapod-tun2socks.aar"))

    implementation("androidx.annotation:annotation:1.9.1")
}

// Директория для JNI библиотек из Go AAR
val jniLibsDir = layout.buildDirectory.dir("generated/jniLibs")

// Задача для извлечения .so файлов из Go AAR
tasks.register<Copy>("extractGoNativeLibs") {
    val goAarFile = file("../output/teapod-tun2socks.aar")
    
    // Используем closure для отложенного вычисления zipTree
    from(provider { zipTree(goAarFile) }) {
        include("jni/**/*.so")
    }
    into(jniLibsDir)
    
    onlyIf { goAarFile.exists() }
}

// Настраиваем JNI source sets — чтобы .so файлы попали в AAR
android.sourceSets.getByName("main") {
    jniLibs.srcDir(jniLibsDir)
}

// Убеждаемся, что JNI библиотеки извлекаются перед сборкой
tasks.configureEach {
    if (name.startsWith("merge") && name.contains("JniLibFolders")) {
        dependsOn("extractGoNativeLibs")
    }
}

// Задача для создания итогового fat AAR
tasks.register("assembleFatAar") {
    dependsOn("assembleRelease")
    
    doLast {
        // Читаем целевую архитектуру из параметров (если есть)
        val targetArch = project.findProperty("targetArch") as? String
        
        // Ищем AAR файл в директории outputs/aar/
        val aarDir = layout.buildDirectory.dir("outputs/aar").get().asFile
        val kotlinAarFile = aarDir.listFiles()?.find { it.name.endsWith("-release.aar") }
            ?: throw GradleException("Kotlin AAR file not found in ${aarDir.absolutePath}")
            
        val goAarFile = file("../output/teapod-tun2socks.aar")
        if (!goAarFile.exists()) {
            throw GradleException("Go AAR file not found at ${goAarFile.absolutePath}")
        }
        
        val outputDir = layout.buildDirectory.dir("outputs/fat-aar").get().asFile
        
        // Считываем версию библиотеки
        val libVersion = project.findProperty("libraryVersion") as? String ?: "1.0.0"
        
        // Имя выходного файла зависит от версии и архитектуры
        val baseName = "teapod-tun2socks"
        val outputFileName = if (targetArch.isNullOrBlank()) "$baseName-$libVersion.aar" else "$baseName-$targetArch-$libVersion.aar"
        val fatAarFile = file("${outputDir}/$outputFileName")
        val tempDir = file("${outputDir}/temp-${targetArch ?: "universal"}")
        
        // Очищаем временную директорию
        tempDir.deleteRecursively()
        tempDir.mkdirs()
        
        println("📦 Сборка AAR v$libVersion для ${targetArch ?: "all architectures"}...")
        println("   Kotlin AAR: ${kotlinAarFile.name}")
        println("   Go AAR: ${goAarFile.name}")
        
        // 1. Распаковываем Kotlin AAR
        copy {
            from(zipTree(kotlinAarFile))
            into(tempDir)
        }
        
        // 2. Объединяем Go классы
        val goClassesJar = zipTree(goAarFile).matching { include("classes.jar") }.singleFile
        val kotlinClassesJar = zipTree(kotlinAarFile).matching { include("classes.jar") }.singleFile
        
        // Распаковываем Go классы
        val goClassesDir = file("${tempDir}/go-classes")
        goClassesDir.mkdirs()
        copy {
            from(zipTree(goClassesJar))
            into(goClassesDir)
        }
        
        // Распаковываем Kotlin классы
        val kotlinClassesDir = file("${tempDir}/kotlin-classes")
        kotlinClassesDir.mkdirs()
        copy {
            from(zipTree(kotlinClassesJar))
            into(kotlinClassesDir)
        }
        
        // Удаляем старый classes.jar
        file("${tempDir}/classes.jar").delete()
        
        // Создаём объединённый classes.jar
        val mergedClassesDir = file("${tempDir}/merged-classes")
        mergedClassesDir.mkdirs()
        
        // Копируем все классы (Go + Kotlin)
        copy {
            from(goClassesDir, kotlinClassesDir)
            into(mergedClassesDir)
        }
        
        // Создаём JAR с помощью команды jar (должна быть в PATH)
        exec {
            workingDir(mergedClassesDir)
            commandLine("jar", "cf", "${tempDir}/classes.jar", ".")
        }
        
        // Копируем JNI библиотеки из Go AAR (фильтруем по архитектуре если нужно)
        copy {
            from(zipTree(goAarFile)) {
                if (!targetArch.isNullOrBlank()) {
                    include("jni/$targetArch/**/*")
                } else {
                    include("jni/**/*")
                }
            }
            into(tempDir)
        }
        
        // Удаляем временные папки с классами перед упаковкой AAR
        goClassesDir.deleteRecursively()
        kotlinClassesDir.deleteRecursively()
        mergedClassesDir.deleteRecursively()
        
        // 3. Упаковываем итоговый AAR
        ant.withGroovyBuilder {
            "zip"("destfile" to fatAarFile, "basedir" to tempDir)
        }
        
        // 4. Чистим временную директорию
        tempDir.deleteRecursively()
        
        println("AAR создан: ${fatAarFile.absolutePath}")
        println("Размер: ${String.format("%.2f", fatAarFile.length() / (1024.0 * 1024.0))} MB")
    }
}

