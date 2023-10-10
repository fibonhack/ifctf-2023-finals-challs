#include <iostream>
#include <fstream>
#include <vector>
#include <gmpxx.h>
#include <bits/stdc++.h>
#include <chrono>


using namespace std;
using namespace std::chrono;

inline mpz_class mod_inverse(mpz_class a, mpz_class m) {
    mpz_class inverse;
    mpz_invert(inverse.get_mpz_t(), a.get_mpz_t(), m.get_mpz_t());
    return inverse % m;
}

int main(int argc, char** argv) {
    if (argc != 4) {
        cout << "Usage: ./vm <program_file> <n> <g>" << endl;
        return 1;
    }
    string program_file = argv[1];
    mpz_class n = mpz_class(argv[2]);
    mpz_class g = mpz_class(argv[3]);

    mpz_class n_squared = n * n;
    mpz_class neg_tresh = n / 2;

    vector<mpz_class> program;
    ifstream fin(program_file);
    string line;
    while (getline(fin, line)) {
        string token;
        stringstream ss(line);
        while (getline(ss, token, ' ')) {
            program.push_back(mpz_class(token));
        }
    }

    assert(program.size() % 3 == 0);
    assert(program.size() > 3);

    milliseconds start = duration_cast< milliseconds >(
        system_clock::now().time_since_epoch()
    );
    long ip = 0;
    while(ip >= 0 and ip + 2 < program.size()) {
        long a = program[ip].get_si();
        long b = program[ip + 1].get_si();
        long c = program[ip + 2].get_si();

        program[b] = (program[b] * mod_inverse(program[a], n_squared)) % n_squared;

        if ((program[b]-1) / n > neg_tresh || (program[b]-1) / n == 0){
            ip = c;
        } else {
            ip += 3;
        }
    }

    cout << "Result: " << program[0].get_str() << endl;
    milliseconds end = duration_cast< milliseconds >(
        system_clock::now().time_since_epoch()
    );
    cout << "Time: " << (end - start).count() << "ms" << endl;

}