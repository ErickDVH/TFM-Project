-------------------English Version------------------

Enumeration of domain-related assets

Presentation

It is a tool for domain research and analysis. Designed to help security researchers, system administrators and cybersecurity enthusiasts, it allows you to obtain and correlate a wide variety of information about web domains. This tool collects data from a variety of sources, including Google searches, DNS records, WHOIS information, SSL/TLS certificates, Wayback Machine, and social media links.

Description

The tool offers a number of functionalities for domain analysis and comparison:

Google search: Find domain-related links on the web. Subdomains: Identify subdomains using crt.sh. DNS Records: Scans DNS records for the specified domain. WHOIS information: Gets details about the domain record. SSL/TLS Certificates: Retrieves information about SSL/TLS certificates associated with the domain. Wayback Machine: Search for historical Wayback Machine links to the domain and find external links. Social Media: Search for domain-related links on major social networks. It also allows for domain comparisons based on these criteria and provides a detailed or simplified summary of the information found.

Installation

To use the tool, follow these steps:

Clone the repository:

Copy code: "git clone https://github.com/ErickDVH/TFM-Project.git"

Navigate to the project directory:

Copy code: "cd TFM-Project"

Install dependencies: Make sure you have pip installed and then run:

Copy code: "pip install -r requirements.txt"

Use

Get a Google Custom Search API key: Sign up for Google Cloud Platform and enable the Google Custom Search API to get your API key.

Create a Custom Search ID (CX): Set up a custom search engine in Google Custom Search to get your Custom Search ID (CX).

Run the tool: Start the tool by running the main script:

Copy code: "python FunctionalTool.py"

Follow the on-screen instructions: You will be asked to enter your API key, custom search ID and select the mode of operation (analysis of one or more domains from a CSV file).


-------------------Versión Español------------------

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

Copiar código: "git clone https://github.com/ErickDVH/TFM-Project.git"

Navega al directorio del proyecto:

Copiar código: "cd TFM-Project"

Instala las dependencias: Asegúrate de tener pip instalado y luego ejecuta:

Copiar código: "pip install -r requirements.txt"

Uso

Obtén una clave API de Google Custom Search: Regístrate en Google Cloud Platform y habilita la API de Google Custom Search para obtener tu clave API.

Crea un ID de búsqueda personalizada (CX): Configura un motor de búsqueda personalizada en Google Custom Search para obtener tu ID de búsqueda personalizada (CX).

Ejecuta la herramienta: Inicia la herramienta ejecutando el script principal:

Copiar código: "python HerramientaFuncional.py"

Sigue las instrucciones en pantalla: Se te pedirá que ingreses tu clave API, el ID de búsqueda personalizada y que selecciones el modo de operación (análisis de un dominio o varios desde un archivo CSV).
