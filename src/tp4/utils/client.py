"""
Client TCP pour le challenge.
"""
from .config import logger, SERVER_IP, SERVER_PORT, TIMEOUT

# Import pwntools
try:
    from pwn import remote, context
    context.log_level = "error"
    PWNTOOLS_OK = True
except ImportError:
    PWNTOOLS_OK = False
    logger.error("pwntools requis: pip install pwntools")


def run_challenge(ip, port, decoder, max_rounds=200):
    """
    Se connecte et résout les challenges.
    
    Args:
        ip: IP du serveur
        port: Port
        decoder: Fonction de décodage
        max_rounds: Max rounds
        
    Returns:
        bool: True si flag trouvé
    """
    if not PWNTOOLS_OK:
        return False
    
    print("=" * 50)
    print("TP4 - CRAZY DECODER")
    print(f"Serveur: {ip}:{port}")
    print("=" * 50)
    
    try:
        conn = remote(ip, port, timeout=TIMEOUT)
        print("Connecté!")
    except Exception as e:
        print(f"Erreur connexion: {e}")
        return False
    
    round_num = 0
    success = 0
    
    try:
        while round_num < max_rounds:
            # Recevoir
            try:
                data = conn.recv(timeout=5).decode("utf-8", errors="ignore")
            except:
                print("Pas de données")
                break
            
            if not data:
                break
            
            data_lower = data.lower()
            
            # Flag trouvé ?
            if "flag" in data_lower or "gg" in data_lower:
                print("\n" + "=" * 50)
                print("FLAG TROUVE!")
                print(data)
                print("=" * 50)
                return True
            
            # Succès intermédiaire
            if "suivant" in data_lower:
                success += 1
                continue
            
            # Échec
            if "non" in data_lower and len(data) < 20:
                continue
            
            # C'est un challenge
            round_num += 1
            
            # Extraire après ":"
            to_decode = data
            if ":" in data:
                to_decode = data.split(":", 1)[1].strip()
            
            # Décoder
            answer = decoder(to_decode)
            print(f"Round {round_num}: {to_decode[:40]}... -> {answer[:30]}...")
            
            conn.sendline(answer.encode())
    
    except KeyboardInterrupt:
        print("\nInterrompu")
    finally:
        conn.close()
    
    print(f"\nTerminé: {success} succès sur {round_num} rounds")
    return False
