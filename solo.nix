{ lib, python3 }:

python3.pkgs.buildPythonPackage {
  pname = "solo";
  version = "0.0.2";
  format = "pyproject";

  src = ./.;

  # install hatchling *into* the build environment so that
  # PEP 517 sees hatchling.build as an available backend:
  nativeBuildInputs = with python3.pkgs; [ hatchling ];

  propagatedBuildInputs = with python3.pkgs; [
    click
    cryptography
    ecdsa
    fido2
    intelhex
    pyserial
    pyusb
    requests
  ];

  pythonImportsCheck = [ "solo" ];

  # nativeCheckInputs = with python3.pkgs; [ pytest ];
  # checkPhase = ''
  #   pytest
  # '';

  meta = with lib; {
    description = "IndexLib is a library for indexing and searching text data";
    homepage = "";
    license = licenses.mit;
    maintainers = with maintainers; [ ];
    platforms = platforms.unix;
    broken = false;
  };
}
