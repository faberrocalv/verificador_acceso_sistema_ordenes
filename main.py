from abc import ABC, abstractmethod


# Clase abstracta
class ManejadorBase(ABC):
    def __init__(self, proximo_manejador=None):
        self._proximo_manejador = proximo_manejador

    @abstractmethod
    def manejar_solicitud(self, solicitud):
        if self._proximo_manejador:
            return self._proximo_manejador.manejar_solicitud(solicitud)
        else:
            return None

# Clases heredadas de la clase abstracta
class ManejadorAutenticacion(ManejadorBase):
    def manejar_solicitud(self, solicitud):
        # Realizar autenticación
        resultado_autenticacion = autenticar(solicitud.datos_solicitud['credenciales'])
        if resultado_autenticacion[0]:
            print('{} autentificado correctamente'.format(resultado_autenticacion[1]))
            return super().manejar_solicitud(solicitud)
        else:
            return 'Autenticación fallida'


class ManejadorSanearDatos(ManejadorBase):
    def manejar_solicitud(self, solicitud):
        # Realizar validación de datos
        if validar_datos(solicitud.datos_solicitud):
            print('Datos de solicitud completos')
            return super().manejar_solicitud(solicitud)
        else:
            return 'Datos de solictud inválidos'


class ManejadorValidacionIP(ManejadorBase):
    # Se modifica el constructor de la clase padre para poder recibir la 
    # informacion de los intentos fallidos (sin alterar las funciones base)
    def __init__(self, proximo_manejador=None, intentos_fallidos={}):
        super().__init__(proximo_manejador)
        self.intentos_fallidos = intentos_fallidos

    def manejar_solicitud(self, solicitud):
        # Protección contra ataques de fuerza bruta por IP
        if self.intentos_fallidos.get(solicitud.datos_solicitud['direccion_ip'], 0) < 3:
            print('La dirección IP de la solicitud es confiable')
            return super().manejar_solicitud(solicitud)
        else:
            return 'Demasiados intentos fallidos desde esta dirección IP'


class ManejadorCache(ManejadorBase):
    # Se modifica el constructor de la clase padre para poder recibir la 
    # informacion del cache (sin alterar las funciones base)
    def __init__(self, proximo_manejador=None, cache={}):
        super().__init__(proximo_manejador)
        self.cache = cache

    def manejar_solicitud(self, solicitud):
        # Manejar respuesta cacheada
        # Generar el id unico de la solicitud para ver si tiene una respuesta en cache
        clave_hash = solicitud.datos_solicitud['credenciales']['usuario'] + solicitud.datos_solicitud['credenciales']['clave'] + solicitud.datos_solicitud['direccion_ip']
        respuesta_en_cache = self.cache.get(hash(clave_hash))
        if respuesta_en_cache:
            print('Se encontró una respuesta a la solicitud en cache:')
            return respuesta_en_cache
        else:
            respuesta_en_cache = 'Acceso autorizado'
            print('Respuesta a la solicitud guardada en cache:')
            self.cache[hash(clave_hash)] = respuesta_en_cache
            return respuesta_en_cache


# Funciones para autenticación y validación de datos
def autenticar(credenciales) -> tuple:
    # Implementación de autenticación
    if (credenciales['usuario'] == 'usuario') and (credenciales['clave'] == 'miclave'):
        return (True, 'Usuario Normal')
    elif (credenciales['usuario'] == 'admin') and (credenciales['clave'] == 'miclaveadmin'):
        return (True, 'Admin')
    else:
        return (False,)

def validar_datos(datos_solicitud) -> bool:
    # Implementación de validación de datos
    if ('credenciales' in datos_solicitud) and ('direccion_ip' in datos_solicitud):
        return True
    else:
        return False

# Clases para simular la verificacion de una solicitud enviada
class Verificacion:
    # Al crearse la clase se instancian las validaciones
    def __init__(self, intentos_fallidos: dict, cache: dict):
        self.intentos_fallidos = intentos_fallidos
        self.cache = cache
        self.cadena_validaciones = ManejadorAutenticacion(
            ManejadorSanearDatos(
                ManejadorValidacionIP(
                    ManejadorCache(cache=self.cache),
                    intentos_fallidos=self.intentos_fallidos
                )
            )
        )

    # Metodo para procesar una solictud entrante
    def procesar_solicitud(self, solicitud):
        return self.cadena_validaciones.manejar_solicitud(solicitud)
    

class Solicitud:
    # Recibe en su constructor los datos que debe llevar una solicitud
    def __init__(self, credenciales: dict, direccion_ip: str):
        self.datos_solicitud = {
            'credenciales': credenciales,
            'direccion_ip': direccion_ip
        }


if __name__ == '__main__': 
    # Procesamiento de una solicitud entrante
    solicitud = Solicitud(credenciales={'usuario': 'usuario', 'clave': 'miclave'}, direccion_ip='192.168.1.1')
    #solicitud = Solicitud(credenciales={'usuario': 'admin', 'clave': 'miclaveadmin'}, direccion_ip='192.102.1.1')
    # El sistema internamente lleva el registro de solicitudes fallidas y del cache
    intentos_fallidos = {
        '192.168.1.1': 0,
        '192.102.1.1': 0
    }
    # Se guarda una respuesta a la solicitud, generando un id o clave unica (compuesta) para identificarla
    cache = {
        hash('usuario'+'miclave'+'192.168.1.1'): 'Acceso autorizado'
    }
    # Una vez recibida la solicitud, la fincionalidad del sistema de ordenes encargada de verificar la misma, la procesa,
    # y emite una respuesta, dando acceso o no al sistema de ordenes
    verificacion = Verificacion(intentos_fallidos=intentos_fallidos, cache=cache)
    respuesta = verificacion.procesar_solicitud(solicitud)
    print(respuesta)
