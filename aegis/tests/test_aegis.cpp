/**
 * Copyright (c) 2017 Armando Faz <armfazh@ic.unicamp.br>.
 * Institute of Computing.
 * University of Campinas, Brazil.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, version 2 or greater.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
#include <gtest/gtest.h>
#include <prng/flo-random.h>
#include <aegis.h>

#define TEST_TIMES 1000

//static std::ostream &operator<<(std::ostream &os, const Digest &d) {
//  int i = 0;
//  for (i = 0; i < SHA256_DigestSize; i++) {
//    os << std::setbase(16) << std::setfill('0') << std::setw(2)
//       << static_cast<int>(d[i]);
//  }
//  return os << std::endl;
//}
//
//static std::string stream(uint8_t* in, int len) {
//  int i = 0;
//  std::stringstream buf;
//  for (i = 0; i < len; i++) {
//    buf << std::setbase(16) << std::setfill('0') << std::setw(2)
//        << static_cast<int>(in[i]);
//  }
//  buf << std::endl;
//  return buf.str();
//}
