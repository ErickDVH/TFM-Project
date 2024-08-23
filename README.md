Enumeración de activos relacionados con un dominio
Presentación
Es una herramienta  para la investigación y análisis de dominios. Diseñada para ayudar a los investigadores de seguridad, administradores de sistemas y entusiastas de la ciberseguridad, permite obtener y correlacionar una amplia variedad de información sobre dominios web. Esta herramienta reúne datos de diversas fuentes, incluyendo búsquedas en Google, registros DNS, información WHOIS, certificados SSL/TLS, Wayback Machine, y enlaces en redes sociales.

Descripción
La herramienta ofrece una serie de funcionalidades para el análisis y la comparación de dominios:

Búsqueda en Google: Encuentra enlaces relacionados con el dominio en la web.
Subdominios: Identifica subdominios usando crt.sh.
Registros DNS: Analiza registros DNS para el dominio especificado.
Información WHOIS: Obtiene detalles sobre el registro del dominio.
Certificados SSL/TLS: Recupera información sobre certificados SSL/TLS asociados al dominio.
Wayback Machine: Busca enlaces históricos de Wayback Machine para el dominio y encuentra enlaces externos.
Redes Sociales: Busca enlaces relacionados con el dominio en principales redes sociales.
Además, permite comparar dominios en base a estos criterios y proporciona un resumen detallado o simplificado de la información encontrada.

Instalación
Para utilizar la herramienta, sigue estos pasos:

Clona el repositorio:

bash
Copiar código
git clone https://github.com/ErickDVH/TFM-Project.git
Navega al directorio del proyecto:

bash
Copiar código
cd TFM-Project
Instala las dependencias: Asegúrate de tener pip instalado y luego ejecuta:

bash
Copiar código
pip install -r requirements.txt
Uso
Obtén una clave API de Google Custom Search: Regístrate en Google Cloud Platform y habilita la API de Google Custom Search para obtener tu clave API.

Crea un ID de búsqueda personalizada (CX): Configura un motor de búsqueda personalizada en Google Custom Search para obtener tu ID de búsqueda personalizada (CX).

Ejecuta la herramienta: Inicia la herramienta ejecutando el script principal:

bash
Copiar código
python HerramientaFuncional.py
Sigue las instrucciones en pantalla: Se te pedirá que ingreses tu clave API, el ID de búsqueda personalizada y que selecciones el modo de operación (análisis de un dominio o varios desde un archivo CSV).
